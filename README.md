angr_ctf题解

从第三章开始我本地(ubuntu20.04)编译出来后跑angr跑不出结果。
原因是在main函数开头有以下代码
```assembly
call    __x86_get_pc_thunk_bx
add     eax, (offset _GLOBAL_OFFSET_TABLE_ - $)
```
然后_GLOBAL_OFFSET_TABLE_的地址就一直保存在ebx中.也就是说从中间开始执行需要设置下ebx
ps:基于IP寻址(IP-relative addressing modes)似乎是x64引入，x86并不支持
