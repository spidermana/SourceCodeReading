# AFL 

Offical Documentation: https://afl-1.readthedocs.io/en/latest/index.html

AFL Environment：https://github.com/mirrorer/afl/blob/master/docs/env_variables.txt

AFL White paper(unofficial)：https://thepatrickstar.github.io/afl-white-paper/

## AFL Fuzzer & Strategy

每个Fuzz策略的详解：https://lcamtuf.blogspot.com/2014/08/binary-fuzzing-strategies-what-works.html

决定性和非决定性的差别：前期的大多阶段都是决定性的，之后随机化和大组会的阶段一般是非决定性的。

> It is somewhat notable that especially early on, most of the work done by afl-fuzz is actually highly deterministic, and progresses to random stacked modifications and test case splicing only at a later stage. The deterministic strategies include:
> 1. Sequential bit flips with varying lengths and stepovers,
> 2. Sequential addition and subtraction of small integers,
> 3. Sequential insertion of known interesting integers (0, 1, INT_MAX, etc),
> 
> The purpose of opening with deterministic steps is related to their tendency to produce compact test cases and small diffs between the non-crashing and crashing inputs.
> 
> With deterministic fuzzing out of the way, the non-deterministic steps include stacked bit flips, insertions, deletions, arithmetics, and splicing of different test cases.


S和M fuzz instance的区别：
> The difference between the -M and -S modes is that the master instance will still perform deterministic checks; while the secondary instances will proceed straight to random tweaks. 

AFL作者对AFL的局限和实现特点的描述：不会考虑变异位置之间的关系，也不会考虑变异对程序状态引起的变化【这也就是大家现在在优化的地方，其实就是加入程序状态和关系学习的考量】。AFL只依赖进化或说遗传算法。

> AFL generally does not try to reason about the relationship between specific mutations and program states; the fuzzing steps are nominally blind, and are guided only by the evolutionary design of the input queue.