/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - wrapper for GNU as
   ---------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   The sole purpose of this wrapper is to preprocess assembly files generated
   by GCC / clang and inject the instrumentation bits included from afl-as.h. It
   is automatically invoked by the toolchain when compiling programs using
   afl-gcc / afl-clang.

   Note that it's an explicit non-goal to instrument hand-written assembly,
   be it in separate .s files or in __asm__ blocks. The only aspiration this
   utility has right now is to be able to skip them gracefully and allow the
   compilation process to continue.

   That said, see experimental/clang_asm_normalize/ for a solution that may
   allow clang users to make things work even with hand-crafted assembly. Just
   note that there is no equivalent for GCC.

*/

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include "afl-as.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/time.h>

static u8** as_params;          /* Parameters passed to the real 'as'   */
            //传递给真实as的参数

static u8*  input_file;         /* Originally specified input file      */
static u8*  modified_file;      /* Instrumented file for the real 'as'  */

static u8   be_quiet,           /* Quiet mode (no stderr output)        */
            clang_mode,         /* Running in clang mode?               */
            pass_thru,          /* Just pass data through?              */
            just_version,       /* Just show version?                   */
            sanitizer;          /* Using ASAN / MSAN                    */

static u32  inst_ratio = 100,   /* Instrumentation probability (%)      */
            as_par_cnt = 1;     /* Number of params to 'as'             */

/* If we don't find --32 or --64 in the command line, default to 
   instrumentation for whichever mode we were compiled with. This is not
   perfect, but should do the trick for almost all use cases. */

#ifdef WORD_SIZE_64

static u8   use_64bit = 1;

#else

static u8   use_64bit = 0;

#ifdef __APPLE__
#  error "Sorry, 32-bit Apple platforms are not supported."
#endif /* __APPLE__ */

#endif /* ^WORD_SIZE_64 */


/* Examine and modify parameters to pass to 'as'. Note that the file name
   is always the last parameter passed by GCC, so we exploit this property
   to keep the code simple. */

static void edit_params(int argc, char** argv) {

  u8 *tmp_dir = getenv("TMPDIR"), *afl_as = getenv("AFL_AS");
  u32 i;

#ifdef __APPLE__

  u8 use_clang_as = 0;

  /* On MacOS X, the Xcode cctool 'as' driver is a bit stale and does not work
     with the code generated by newer versions of clang that are hand-built
     by the user. See the thread here: http://goo.gl/HBWDtn.

     To work around this, when using clang and running without AFL_AS
     specified, we will actually call 'clang -c' instead of 'as -q' to
     compile the assembly file.

     The tools aren't cmdline-compatible, but at least for now, we can
     seemingly get away with this by making only very minor tweaks. Thanks
     to Nico Weber for the idea. */

  if (clang_mode && !afl_as) {

    use_clang_as = 1;

    afl_as = getenv("AFL_CC");
    if (!afl_as) afl_as = getenv("AFL_CXX");
    if (!afl_as) afl_as = "clang";

  }

#endif /* __APPLE__ */

  /* Although this is not documented, GCC also uses TEMP and TMP when TMPDIR
     is not set. We need to check these non-standard variables to properly
     handle the pass_thru logic later on. */

  if (!tmp_dir) tmp_dir = getenv("TEMP");
  if (!tmp_dir) tmp_dir = getenv("TMP");
  if (!tmp_dir) tmp_dir = "/tmp";       //会根据TEMP、TMP来确定一个临时目录。【未指定则为/tmp】
  //依次检查是否存在TMPDIR/TEMP/TMP环境变量，如果存在就设置，如果都不存在就设置tmp_dir为”/tmp”
  as_params = ck_alloc((argc + 32) * sizeof(u8*));

  as_params[0] = afl_as ? afl_as : (u8*)"as";

  as_params[argc] = 0;

  for (i = 1; i < argc - 1; i++) {

    if (!strcmp(argv[i], "--64")) use_64bit = 1;
    else if (!strcmp(argv[i], "--32")) use_64bit = 0;

#ifdef __APPLE__

    /* The Apple case is a bit different... */

    if (!strcmp(argv[i], "-arch") && i + 1 < argc) {

      if (!strcmp(argv[i + 1], "x86_64")) use_64bit = 1;
      else if (!strcmp(argv[i + 1], "i386"))
        FATAL("Sorry, 32-bit Apple platforms are not supported.");

    }

    /* Strip options that set the preference for a particular upstream
       assembler in Xcode. */

    if (clang_mode && (!strcmp(argv[i], "-q") || !strcmp(argv[i], "-Q")))
      continue;

#endif /* __APPLE__ */

    as_params[as_par_cnt++] = argv[i];

  }

#ifdef __APPLE__

  /* When calling clang as the upstream assembler, append -c -x assembler
     and hope for the best. */

  if (use_clang_as) {

    as_params[as_par_cnt++] = "-c";
    as_params[as_par_cnt++] = "-x";
    as_params[as_par_cnt++] = "assembler";

  }

#endif /* __APPLE__ */

  input_file = argv[argc - 1];        //认为文件名永远是传递给GCC的最后一个参数。input_file为原始文件

  if (input_file[0] == '-') {

    if (!strcmp(input_file + 1, "-version")) {  //最后一个参数是--version，设置just_version为1
      just_version = 1;
      modified_file = input_file;
      goto wrap_things_up;
    }

    if (input_file[1]) FATAL("Incorrect use (not called through afl-gcc?)");  //必须是文件名作为最后一个参数，不然不让使用afl
      else input_file = NULL;

  } else {

    /* Check if this looks like a standard invocation as a part of an attempt
       to compile a program, rather than using gcc on an ad-hoc .s file in
       a format we may not understand. This works around an issue compiling
       NSS. */

    if (strncmp(input_file, tmp_dir, strlen(tmp_dir)) &&
        strncmp(input_file, "/var/tmp/", 9) &&
        strncmp(input_file, "/tmp/", 5)) pass_thru = 1;   //判断本来这个input的文件是不是在tmp目录下【设置pass_thru=1】

  }

  modified_file = alloc_printf("%s/.afl-%u-%u.s", tmp_dir, getpid(),
                               (u32)time(NULL));  //在临时目录下设置一个文件名【基本上是唯一的，包含时间戳、pid等】->之后要对这个文件进行插桩。

wrap_things_up:

  as_params[as_par_cnt++] = modified_file;  //modified file作为as_params的最后一个参数。【只是名称，真实还未创建】
  as_params[as_par_cnt]   = NULL;

}


/* Process input file, generate modified_file. Insert instrumentation in all
   the appropriate places. */
//处理input file，通过在适当的位置插桩，产生modified_file
static void add_instrumentation(void) {

  static u8 line[MAX_LINE];

  FILE* inf;
  FILE* outf;
  s32 outfd;
  u32 ins_lines = 0;  //记录现在处理了多少指令了

  u8  instr_ok = 0, skip_csect = 0, skip_next_label = 0,
      skip_intel = 0, skip_app = 0, instrument_next = 0;

#ifdef __APPLE__

  u8* colon_pos;

#endif /* __APPLE__ */

  if (input_file) {

    inf = fopen(input_file, "r"); //打开inputfile作为inf
    if (!inf) PFATAL("Unable to read '%s'", input_file);

  } else inf = stdin;

  outfd = open(modified_file, O_WRONLY | O_EXCL | O_CREAT, 0600); //创建modified file，作为outfd
  //参考diff between open and fopen：https://stackoverflow.com/questions/1658476/c-fopen-vs-open
  if (outfd < 0) PFATAL("Unable to write to '%s'", modified_file);

  outf = fdopen(outfd, "w");  
  //fdopen取一个现存的文件描述符，并使一个标准的I / O流与该描述符相结合。
  //此函数常用于由创建管道和网络通信通道函数获得的描述符。
  //因为这些特殊类型的文件不能用标准I/O fopen函数打开，
  //首先必须先调用设备专用函数以获得一个文件描述符，然后用fdopen使一个标准I/O流与该描述符相结合。
  //成为一个文件流

  //fopen、fdopen：https://man7.org/linux/man-pages/man3/fopen.3.html
  //这里只是将open打开之后的fd转换为FILE *【和fopen打开的效果是一样的】
  if (!outf) PFATAL("fdopen() failed");  
  //以gcc为例，gcc的处理流程：预处理->编译(cc1)->汇编(as)->连接(ld)
  //因此我们在进入汇编阶段的时候，我们生成的.S文件包含了一条条汇编语句
  //经过as之后会成为.o目标文件。
  //因此我们通过封装as，在解析汇编语句的时候，插入汇编形式的桩子，之后再传给real as，转换成machine code
  //可以通过gcc -S获得汇编器as处理之前的文件。

  //这里注意只在.text部分进行插桩，这部分涉及到多平台以及优化后的汇编文件格式。
  while (fgets(line, MAX_LINE, inf)) {  //从input_file中按行读取一条条汇编指令，直到读取完所有行
  //the instrumentation trampoline是插桩的程序片段
  
  //一般来说，trampoline会一直延迟到最靠近指令的时候再写入。
  //会在labels、macros、comments之后写入。
    /* In some cases, we want to defer writing the instrumentation trampoline
       until after all the labels, macros, comments, etc. If we're in this
       mode, and if the line starts with a tab followed by a character, dump
       the trampoline now. */
  
  //我们在判断到有一个tab，然后紧跟着一个字符的时候，认为这是新的一条指令
  //故写入trampoline【因为label等都是顶格的，而一些字符、常量都是tab之后以.global、.string开头的，第一个不是字母】
  //即line[0] == '\t' && isalpha(line[1]
    if (!pass_thru && !skip_intel && !skip_app && !skip_csect && instr_ok &&
        instrument_next && line[0] == '\t' && isalpha(line[1])) {

      fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
              R(MAP_SIZE)); //把trampoline写入outf【根据use_64bit决定是哪种类型的桩子】
              //注意这里的R(MAP_SIZE)会产生0~1<<16【覆盖率map表大小】的随机数，写入trampoline_fmt_64中
              //填充"movq $0x%08x, %%rcx"中的$0x%08x，写入%ecx寄存器，作为块id
              //因此在插桩的时候，执行R(MAP_SIZE)，确定了块id
              //在生成outf插桩后的文件时，桩点已经有了块id
      instrument_next = 0;
      ins_lines++;

    }

    /* Output the actual line, call it a day in pass-thru mode. */

    fputs(line, outf);  //把一条条在inf中遍历的line【指令】写入outf【隐含着，先执行插桩代码，再执行指令】

    if (pass_thru) continue;

    /* All right, this is where the actual fun begins. For one, we only want to
       instrument the .text section. So, let's keep track of that in processed
       files - and let's set instr_ok accordingly. */
    //注意我们只插桩.text section
    if (line[0] == '\t' && line[1] == '.') {

      /* OpenBSD puts jump tables directly inline with the code, which is
         a bit annoying. They use a specific format of p2align directives
         around them, so we use that as a signal. */

      if (!clang_mode && instr_ok && !strncmp(line + 2, "p2align ", 8) &&
          isdigit(line[10]) && line[11] == '\n') skip_next_label = 1;

      if (!strncmp(line + 2, "text\n", 5) ||  //
          !strncmp(line + 2, "section\t.text", 13) ||
          !strncmp(line + 2, "section\t__TEXT,__text", 21) ||
          !strncmp(line + 2, "section __TEXT,__text", 21)) {  //MaxOS： __TEXT,__text
        instr_ok = 1; //是text段才进行插桩【要考虑多个平台下的可能】
        continue; 
      }

      if (!strncmp(line + 2, "section\t", 8) ||
          !strncmp(line + 2, "section ", 8) ||
          !strncmp(line + 2, "bss\n", 4) ||
          !strncmp(line + 2, "data\n", 5)) {
        instr_ok = 0; //对于这些段，不设置标志位instr_ok，因此这些部分不插桩。
        continue;
      }

    }

    /* Detect off-flavor assembly (rare, happens in gdb). When this is
       encountered, we set skip_csect until the opposite directive is
       seen, and we do not instrument. */

    if (strstr(line, ".code")) {

      if (strstr(line, ".code32")) skip_csect = use_64bit;  //对于64位的程序，只插桩64-bits的指令，否则，对于32位的程序只插桩32位的指令。
      if (strstr(line, ".code64")) skip_csect = !use_64bit;

    }

    /* Detect syntax changes, as could happen with hand-written assembly.
       Skip Intel blocks, resume instrumentation when back to AT&T. */

    if (strstr(line, ".intel_syntax")) skip_intel = 1;
    if (strstr(line, ".att_syntax")) skip_intel = 0;  //只对AT&T汇编插桩

    /* Detect and skip ad-hoc __asm__ blocks, likewise skipping them. */

    if (line[0] == '#' || line[1] == '#') { //在编译之后得到.S文件中，原来手写的内联汇编会被#APP~#NO_APP包含

      if (strstr(line, "#APP")) skip_app = 1;     //不对内联汇编插桩
      if (strstr(line, "#NO_APP")) skip_app = 0;  //直到内联汇编结束

    }

    /* If we're in the right mood for instrumenting, check for function
       names or conditional labels. This is a bit messy, but in essence,
       we want to catch:

         ^main:      - function entry point (always instrumented)
         ^.L0:       - GCC branch label   【gcc产生的分支label】
         ^.LBB0_0:   - clang branch label (but only in clang mode)  【clang产生的分支label，所谓分支就是和控制流跳转相关的label】
         ^\tjnz foo  - conditional branches
        【\t是tab，然后是jnz label】
       ...but not:【以下不插桩】

         ^# BB#0:    - clang comments
         ^ # BB#0:   - ditto
         ^.Ltmp0:    - clang non-branch labels  【clang产生的非分支labels】
         ^.LC0       - GCC non-branch labels    【GCC产生的非分支labels，比如常量位置】
         ^.LBB0_0:   - ditto (when in GCC mode)
         ^\tjmp foo  - non-conditional jumps
        【\t是tab，然后是jmp label】

       Additionally, clang and GCC on MacOS X follow a different convention
       with no leading dots on labels, hence the weird maze of #ifdefs
       later on.

     */

    if (skip_intel || skip_app || skip_csect || !instr_ok ||
        line[0] == '#' || line[0] == ' ') continue;   //本身已经被pass了或是注释代码，就不需要继续考虑了。

    /* Conditional branch instruction (jnz, etc). We append the instrumentation
       right after the branch (to instrument the not-taken path) and at the
       branch destination label (handled later on). */

    if (line[0] == '\t') {

      if (line[1] == 'j' && line[2] != 'm' && R(100) < inst_ratio) {  //间接跳转指令插桩，按照给定的inst_ratio来确定插桩的比例【概率型插桩】，默认都插桩。

        fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
                R(MAP_SIZE));

        ins_lines++;  

      }

      continue;

    }

    /* Label of some sort. This may be a branch destination, but we need to
       tread carefully and account for several different formatting
       conventions. */

#ifdef __APPLE__

    /* Apple: L<whatever><digit>: */

    if ((colon_pos = strstr(line, ":"))) {

      if (line[0] == 'L' && isdigit(*(colon_pos - 1))) {

#else

    /* Everybody else: .L<whatever>: */
    //考虑.L<whatever>:
    if (strstr(line, ":")) {      //先查冒号

      if (line[0] == '.') {       //再查点号.

#endif /* __APPLE__ */

        /* .L0: or LBB0_0: style jump destination */

#ifdef __APPLE__

        /* Apple: L<num> / LBB<num> */

        if ((isdigit(line[1]) || (clang_mode && !strncmp(line, "LBB", 3)))
            && R(100) < inst_ratio) {

#else

        /* Apple: .L<num> / .LBB<num> */
        // branch label【不对non-branch label插桩】
        if ((isdigit(line[2]) || (clang_mode && !strncmp(line + 1, "LBB", 3)))
            && R(100) < inst_ratio) {   //也是按照inst_ratio插桩率进行插桩

#endif /* __APPLE__ */

          /* An optimization is possible here by adding the code only if the
             label is mentioned in the code in contexts other than call / jmp.
             That said, this complicates the code by requiring two-pass
             processing (messy with stdin), and results in a speed gain
             typically under 10%, because compilers are generally pretty good
             about not generating spurious intra-function jumps.

             We use deferred output chiefly to avoid disrupting
             .Lfunc_begin0-style exception handling calculations (a problem on
             MacOS X). */

          if (!skip_next_label) instrument_next = 1; else skip_next_label = 0;
          //instrument_next下一条语句才插桩，不对当前label插桩。

        }

      } else {  //非.开头的，就是function 

        /* Function label (always instrumented, deferred mode). */
        instrument_next = 1;    //label的label，永远插桩。下一条插桩。
    
      }
    }
  }
  //到这里就处理完所有的插桩了！
  //afl的插桩基本是分支级插桩【也就是块级插桩，每个branch和function label的插桩】
  if (ins_lines)    //处理完，如果插桩的数量>1，在文件的最后追加main_payload，也就是__afl_maybe_log的定义和实现点。【只写一份】
    fputs(use_64bit ? main_payload_64 : main_payload_32, outf); 

  if (input_file) fclose(inf);
  fclose(outf);     //完成插桩后的汇编文件。

  if (!be_quiet) {

    if (!ins_lines) WARNF("No instrumentation targets found%s.",
                          pass_thru ? " (pass-thru mode)" : "");
    else OKF("Instrumented %u locations (%s-bit, %s mode, ratio %u%%).",
             ins_lines, use_64bit ? "64" : "32",
             getenv("AFL_HARDEN") ? "hardened" : 
             (sanitizer ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio);
    //打印插桩的数目，64-bit/32-bit，插桩模式【asan？hardened？】，以及插桩率。
  }

}


/* Main entry point */

int main(int argc, char** argv) {

  s32 pid;
  u32 rand_seed;
  int status;
  u8* inst_ratio_str = getenv("AFL_INST_RATIO");    //先是从环境变量中拿了AFL_INST_RATIO，即插入指令的密度【插桩率，控制在分支处插桩的概率】

  struct timeval tv;
  struct timezone tz;

  clang_mode = !!getenv(CLANG_ENV_VAR); //判断是clang还是gcc编译

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-as " cBRI VERSION cRST " by <lcamtuf@google.com>\n");
 
  } else be_quiet = 1;

  if (argc < 2) {

    SAYF("\n"
         "This is a helper application for afl-fuzz. It is a wrapper around GNU 'as',\n"
         "executed by the toolchain whenever using afl-gcc or afl-clang. You probably\n"
         "don't want to run this program directly.\n\n"

         "Rarely, when dealing with extremely complex projects, it may be advisable to\n"
         "set AFL_INST_RATIO to a value less than 100 in order to reduce the odds of\n"
         "instrumenting every discovered branch.\n\n");

    exit(1);

  }

  gettimeofday(&tv, &tz);

  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();

  srandom(rand_seed); //初始化随机种子。有助于产生桩点的块id

  edit_params(argc, argv);  //设置汇编器的参数

  if (inst_ratio_str) {   //把 inst_ratio_str转为数字，存储到inst_ratio中【之后在add_instrumentation中使用，随机减少插桩点】

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || inst_ratio > 100) 
      FATAL("Bad value of AFL_INST_RATIO (must be between 0 and 100)");

  }

  if (getenv(AS_LOOP_ENV_VAR))
    FATAL("Endless loop when calling 'as' (remove '.' from your PATH)");

  setenv(AS_LOOP_ENV_VAR, "1", 1);

  /* When compiling with ASAN, we don't have a particularly elegant way to skip
     ASAN-specific branches. But we can probabilistically compensate for
     that... */
  //如果使用 ASAN或者MSAN的话，就会把插入指令的密度降低为 1/3，以加快速度
  //目前没有elegant way to skip ASAN-specific branches【找一下ASAN-specific branches有什么特点？】
  if (getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) {
    sanitizer = 1;
    inst_ratio /= 3;
  }

  if (!just_version) add_instrumentation();
  //插入完指令后，会fork子进程，用来执行真正的as，将插桩后汇编代码文件变成二进制
  if (!(pid = fork())) {  //子进程
    execvp(as_params[0], (char**)as_params);
    FATAL("Oops, failed to execute '%s' - check your PATH", as_params[0]);

  }

  if (pid < 0) PFATAL("fork() failed");
  //父进程等待，子进程执行完毕
  if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  if (!getenv("AFL_KEEP_ASSEMBLY")) unlink(modified_file);  //如果没有设置AFL_KEEP_ASSEMBLY环境变量，使用unlink删除中间产生的插桩汇编文件。

  exit(WEXITSTATUS(status));

}

