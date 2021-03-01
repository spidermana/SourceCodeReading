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
   american fuzzy lop - wrapper for GCC and clang
   ----------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   This program is a drop-in replacement for GCC or clang. The most common way
   of using it is to pass the path to afl-gcc or afl-clang via CC when invoking
   ./configure.

   (Of course, use CXX and point it to afl-g++ / afl-clang++ for C++ code.)

   The wrapper needs to know the path to afl-as (renamed to 'as'). The default
   is /usr/local/lib/afl/. A convenient way to specify alternative directories
   would be to set AFL_PATH.
   
   If AFL_HARDEN is set, the wrapper will compile the target app with various
   hardening options that may help detect memory management issues more
   reliably. You can also specify AFL_USE_ASAN to enable ASAN.

   If you want to call a non-default compiler as a next step of the chain,
   specify its location via AFL_CC or AFL_CXX.

*/
//以上就是介绍一下，afl-as工具是一个wrapper。是drop-in(插入式的，不会影响太多源程序的)
//告诉一些环境变量的含义和怎么使用
//AFL_PATH :AFL的根目录
//AFL_HARDEN :会将目标app的编译过程加入更多的选项，有助于检测到内存管理的问题，结果更加可信
//AFL_USE_ASAN: 加入asan
//AFL_CC or AFL_CXX: 来指定非默认的编译器
#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static u8*  as_path;                /* Path to the AFL 'as' wrapper      */
static u8** cc_params;              /* Parameters passed to the real CC  */ 
            //传递给真实编译器的参数
static u32  cc_par_cnt = 1;         /* Param count, including argv0      */
static u8   be_quiet,               /* Quiet mode                        */
            clang_mode;             /* Invoked as afl-clang*?            */


/* Try to find our "fake" GNU assembler in AFL_PATH or at the location derived
   from argv[0]. If that fails, abort. */
//根据AFL_PATH环境变量或第一个参数arg0=>找到afl-as的位置，存入全局变量as_path中
static void find_as(u8* argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/as", afl_path);

    if (!access(tmp, X_OK)) {
      as_path = afl_path;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);

  }

  slash = strrchr(argv0, '/');

  if (slash) {

    u8 *dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

    tmp = alloc_printf("%s/afl-as", dir);

    if (!access(tmp, X_OK)) {
      as_path = dir;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
    ck_free(dir);

  }

  if (!access(AFL_PATH "/as", X_OK)) {
    as_path = AFL_PATH;
    return;
  }

  FATAL("Unable to find AFL wrapper binary for 'as'. Please set AFL_PATH");
 
}


/* Copy argv to cc_params, making the necessary edits. */
//解析命令行的参数，存储到cc_params中
static void edit_params(u32 argc, char** argv) {

  u8 fortify_set = 0, asan_set = 0;
  u8 *name;

#if defined(__FreeBSD__) && defined(__x86_64__)
  u8 m32_set = 0;
#endif
  //cc_params:存储解析后的参数，全局变量
  cc_params = ck_alloc((argc + 128) * sizeof(u8*));   //ck_alloc分配一个清零且安全的内存区域[这个AFL中内存分配释放相关的函数最终汇总到alloc-inl.h：带检测功能的内存分配和释放操作]
                                                      //保证AFL本身的安全
  name = strrchr(argv[0], '/'); //判断argv[0]，是否是afl-clang++
  if (!name) name = argv[0]; else name++;

  if (!strncmp(name, "afl-clang", 9)) {

    clang_mode = 1;   //如果指定的编译器就是clang，那么clang_mode=1

    setenv(CLANG_ENV_VAR, "1", 1);  //overwrite or create __AFL_CLANG_MODE 环境变量的值为1

    if (!strcmp(name, "afl-clang++")) {
      u8* alt_cxx = getenv("AFL_CXX");  //a non-default compiler，环境变量的设置优先。
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++";
    } else {
      u8* alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"clang";
    }

  } else {
    //GNU Java编译器（GNU Compiler for Java，GCJ）是一个Java编译器。它是GCC（GNU Compiler Collection）的一部分
    //GCJ4.3使用了Eclipse Java编译器作为编译前端
    /* With GCJ and Eclipse installed, you can actually compile Java! The
       instrumentation will work (amazingly). Alas, unhandled exceptions do
       not call abort(), so afl-fuzz would need to be modified to equate
       non-zero exit codes with crash conditions when working with Java
       binaries. Meh. */
    //插桩模块莫名还能支持JAVA。但是因为有一些unhandled exceptions所以AFL本身的操作可能会导致crash【出现non-zero exit】
    //所以收到non-zero exit，不代表是待测程序crash，可能是AFL的错误。所以测试JAVA的误报会多一些。
#ifdef __APPLE__  //On Apple system

    if (!strcmp(name, "afl-g++")) cc_params[0] = getenv("AFL_CXX");
    else if (!strcmp(name, "afl-gcj")) cc_params[0] = getenv("AFL_GCJ");
    else cc_params[0] = getenv("AFL_CC");

    if (!cc_params[0]) {

      SAYF("\n" cLRD "[-] " cRST
           "On Apple systems, 'gcc' is usually just a wrapper for clang. Please use the\n"
           "    'afl-clang' utility instead of 'afl-gcc'. If you really have GCC installed,\n"
           "    set AFL_CC or AFL_CXX to specify the correct path to that compiler.\n");

      FATAL("AFL_CC or AFL_CXX required on MacOS X");

    }

#else

    if (!strcmp(name, "afl-g++")) {
      u8* alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"g++";
    } else if (!strcmp(name, "afl-gcj")) {
      u8* alt_cc = getenv("AFL_GCJ");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcj";
    } else {
      u8* alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcc";
    }

#endif /* __APPLE__ */

  }

  while (--argc) {  //解析剩下的参数
    u8* cur = *(++argv);

    if (!strncmp(cur, "-B", 2)) {

      if (!be_quiet) WARNF("-B is already set, overriding");  //如果-B，已经设置了，那么需要进行覆盖

      if (!cur[2] && argc > 1) { argc--; argv++; }
      continue;

    }

    if (!strcmp(cur, "-integrated-as")) continue;

    if (!strcmp(cur, "-pipe")) continue;

#if defined(__FreeBSD__) && defined(__x86_64__)
    if (!strcmp(cur, "-m32")) m32_set = 1;
#endif

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    cc_params[cc_par_cnt++] = cur;  //cc_par_cnt记录参数个数

  }

  cc_params[cc_par_cnt++] = "-B";       //-B <directory>           Add <directory> to the compiler's search paths【也就是汇编器使用不是原来的as，而是afl-as】
  cc_params[cc_par_cnt++] = as_path;  //find_as中获得的afl-as位置
  //afl会在as_path的目录下，创建一个符号链接，符号名为as【as-> afl-as】。因此会通过-B找到被wrapper过的afl-as进行汇编。

  if (clang_mode)
    cc_params[cc_par_cnt++] = "-no-integrated-as";

  if (getenv("AFL_HARDEN")) {
    //开启AFL_HARDEN，即设置D_FORTIFY_SOURCE=2 and -fstack-protector-all
    //即开启编译器的默认保护机制，更有助于catching non-crashing memory bugs
    //性能减少百分之五
    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }

  if (asan_set) {

    /* Pass this on to afl-as to adjust map density. */

    setenv("AFL_USE_ASAN", "1", 1);   //如果开启了asan，设置环境变量为1

  } else if (getenv("AFL_USE_ASAN")) {  //如果不是在命令行设置，看看环境变量里面有没有
    //要求二选一，独占式，不能都加
    if (getenv("AFL_USE_MSAN"))
      FATAL("ASAN and MSAN are mutually exclusive");

    if (getenv("AFL_HARDEN"))
      FATAL("ASAN and AFL_HARDEN are mutually exclusive");

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=address";

  } else if (getenv("AFL_USE_MSAN")) {

    if (getenv("AFL_USE_ASAN"))
      FATAL("ASAN and MSAN are mutually exclusive");

    if (getenv("AFL_HARDEN"))
      FATAL("MSAN and AFL_HARDEN are mutually exclusive");

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=memory";


  }

  if (!getenv("AFL_DONT_OPTIMIZE")) {   //默认情况下，AFL wrapper会设置优化等级为03.

#if defined(__FreeBSD__) && defined(__x86_64__)

    /* On 64-bit FreeBSD systems, clang -g -m32 is broken, but -m32 itself
       works OK. This has nothing to do with us, but let's avoid triggering
       that bug. */

    if (!clang_mode || !m32_set)
      cc_params[cc_par_cnt++] = "-g";

#else

      cc_params[cc_par_cnt++] = "-g";

#endif

    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";

    /* Two indicators that you're building for fuzzing; one of them is
       AFL-specific, the other is shared with libfuzzer. */

    cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
    cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

  }
  /*
    This Linux-only companion library allows you to instrument strcmp(), memcmp(),
  and related functions to automatically extract syntax tokens passed to any of
  these libcalls. The resulting list of tokens may be then given as a starting
  dictionary to afl-fuzz (the -x option) to improve coverage on subsequent
  fuzzing runs.
*/
/*使用步骤
1.Have built a complete enough corpus to exercise the code that will expose the tokens,
2.Recompile your target with a set of extra options that tell your compiler to not use the built-ins version of strcmp/strncmp/etc,
3.Run every test cases through the new binary with the libtokencap LD_PRELOAD'd.
*/
//这libtokencap东西会允许插桩 strcmp(), memcmp(), and related functions
//由于这些都是相等与否的比较性函数，也就是很多程序的入口参数解析都会判断输入是否合法【比较输入=？xxx】
//因此这个功能就是用于解析程序，判断程序的执行过程，自动化地产生一些syntax tokens【往往是一些常量字符串】=>即字典
//之后可以通过-x选项将这个字典传给afl-fuzz，有助于覆盖率的提升。
  if (getenv("AFL_NO_BUILTIN")) {   //参考：https://github.com/rc0r/afl-fuzz/tree/master/libtokencap
                                    //使用示例：https://doar-e.github.io/blog/2016/11/27/clang-and-passes/
    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";

  }

  cc_params[cc_par_cnt] = NULL; //最后参数解析以NULL结尾

}


/* Main entry point */

int main(int argc, char** argv) {   

  if (isatty(2) && !getenv("AFL_QUIET")) {  // The isatty() function tests whether fildes, an open file descriptor, is associated with a terminal device.
                                            //file descriptors 0, 1 and 2 (aka STDIN_FILENO, STDOUT_FILENO and STDERR_FILENO) are by convention set up to point to your terminal when your program is running from a terminal.

    SAYF(cCYA "afl-cc " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  } else be_quiet = 1;

  if (argc < 2) { //如果用户只输入afl-fuzz

    SAYF("\n"
         "This is a helper application for afl-fuzz. It serves as a drop-in replacement\n"
         "for gcc or clang, letting you recompile third-party code with the required\n"
         "runtime instrumentation. A common use pattern would be one of the following:\n\n"

         "  CC=%s/afl-gcc ./configure\n"
         "  CXX=%s/afl-g++ ./configure\n\n"

         "You can specify custom next-stage toolchain via AFL_CC, AFL_CXX, and AFL_AS.\n"
         "Setting AFL_HARDEN enables hardening optimizations in the compiled code.\n\n",
         BIN_PATH, BIN_PATH);

    exit(1);

  }

  find_as(argv[0]);   //根据afl-clang的前驱路径或AFL-PATH找到afl-as的位置

  edit_params(argc, argv);  //解析afl-clang的参数，解析编译选项，之后传给gcc

  execvp(cc_params[0], (char**)cc_params);  //调用gcc，配上解析的参数，指定as，进行编译。
  //

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;
//afl-gcc就是gcc的一个wraper, 用来设置一下gcc的编译选项，还有就是把汇编器换成afl自己实现的一个汇编器
}
