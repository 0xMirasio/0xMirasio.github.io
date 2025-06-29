---
layout: post
title: GoogleCTF2025 - Multiarch
subtitle: custom emulator with differents arch
tags: [reverse, emulator]
comments: true
---

### GoogleCTF 2025 - Multiarch

We are given the following binary : 

```
-> % file multiarch
multiarch: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[shsegment_metadata]=dc495115eb37cb56a37d5ac691cf406d06f185c7, for GNU/Linux 4.4.0, stripped

-> % xxd crackme.masm
00000000: 4d41 534d 0113 0065 0102 7801 5001 03c8  MASM...e..x.P...
00000010: 022d 0010 4b00 0000 3000 2000 0010 0200  .-..K...0. .....
00000020: 0000 a000 0000 0010 2b00 0000 30ad 2000  ........+...0. .
00000030: 0010 0200 0000 a000 0000 0010 0000 0000  ................
00000040: a000 0000 0020 3713 0000 2039 0500 0030  ..... 7... 9...0
00000050: 0953 6708 6200 0000 0060 0000 0000 30aa  .Sg.b....`....0.
00000060: aaaa aa80 0000 0000 720b 1100 00c5 0200  ........r.......
[...]
```

Based on challenge name, this look like a classical emu/VM challenge with external data to emulate.

# Init

(All functions names are hypotethical and based on observed behavior)

Program start by reading crackme.masm with some metadata.
It check the magic_header "MASM" then read metadata for segments inside : 

```c
// Opens the segments for the emulator.
_QWORD *__fastcall open_segments(const char *masmpath)
{
  FILE *v1; // rax
  FILE *fd; // rbx
  _QWORD *ptr; // rbp
  int *v5; // rax
  char *v6; // rax
  int *v7; // rax
  char *v8; // rax
  _QWORD v9[7]; // [rsp+0h] [rbp-38h] BYREF

  v9[3] = __readfsqword(0x28u);
  v1 = fopen(masmpath, "r");
  fd = v1;
  if ( !v1 )
  {
    v5 = __errno_location();
    v6 = strerror(*v5);
    fprintf(stderr, "[E] couldn't open file %s - %s\n", masmpath, v6);
    return 0LL;
  }
  v9[0] = 0LL;
  v9[1] = 0LL;
  if ( fread(v9, 1uLL, 4uLL, v1) != 4 )
  {
    v7 = __errno_location();
    v8 = strerror(*v7);
    fprintf(stderr, "[E] couldn't read magic - %s\n", v8);
LABEL_9:
    fclose(fd);
    return 0LL;
  }
  if ( strncmp((const char *)v9, "MASM", 4uLL) )
  {
    fwrite("[E] bad magic\n", 1uLL, 0xEuLL, stderr);
    goto LABEL_9;
  }
  ptr = calloc(1uLL, 0x30uLL);
  if ( !(unsigned __int8)read_segments(ptr, 4LL, fd)
    || !(unsigned __int8)read_segments(ptr, 9LL, fd)
    || !(unsigned __int8)read_segments(ptr, 14LL, fd) )
  {
    if ( ptr )
      free_seg((__int64)ptr);
    goto LABEL_9;
  }
  return ptr;
}
```

**read_segments** is quite easy to reverse, we can create a python template for the emulator initialisation : 

```py

class Emulator():
    def __init__(self, masm):
        self.masm = masm
        self.fd = open(masm, "rb")
        self._load_segments()

    def __del__(self):
        self.fd.close()

    def _load_segments(self):
        if self.fd.read(4) != b"MASM":
            sys.stderr.write("[E] bad magic\n")
            sys.exit()

        self.segments_metadata = {}
        self.fd.seek(4)

        self.read_segments(4)
        self.read_segments(9)
        self.read_segments(14)


    def read_segments(self, size_offset):
        self.fd.seek(size_offset)
        segment_type_raw = self.fd.read(1)
        segment_type = struct.unpack("B", segment_type_raw)[0]
        offset_raw = self.fd.read(2)
        offset = struct.unpack("<H", offset_raw)[0]
        size_raw = self.fd.read(2)
        size = struct.unpack("<H", size_raw)[0]
        
        self.fd.seek(offset)
        data = self.fd.read(size)

        print(f"Segment : {segment_type} | offset={offset} | size={size}")
           
        if segment_type == 1:
            self.segments_metadata['code'] = (data, size)
        elif segment_type == 2:
            self.segments_metadata['data'] = (data, size)
        elif segment_type == 3:
            self.segments_metadata['extra'] = (data, size)
        else:
            sys.stderr.write(f"[E] invalid segment type: {segment_type}\n")
            return False

        return True

if __name__ == "__main__":
    emu = Emulator("./crackme.masm")
```

Following segment init, program start to init some sort of emulation context with this function: 

```c
// Initializes the emulator context by allocating memory and copying data from the input file.
emu_ctx *__fastcall initialize_emu_ctx(__int64 segment_metadata)
{
  emu_ctx *emu_ctx; // rbx
  void *v3; // r14
  void *v4; // r13
  void *v5; // r12
  __int64 v6; // r13

  emu_ctx = (emu_ctx *)calloc(1uLL, 0x88uLL);
  v3 = mmap(0LL, 0x1000uLL, 7, 33, 0, 0LL);
  emu_ctx->code = v3;
  v4 = mmap(0LL, 0x1000uLL, 7, 33, 0, 0LL);
  emu_ctx->data = v4;
  emu_ctx->extra = mmap(0LL, 0x1000uLL, 7, 33, 0, 0LL);
  v5 = calloc(1uLL, *(_QWORD *)(segment_metadata + 40));
  emu_ctx->ptr_1 = v5;
  emu_ctx->check_flag_env = check_flag_env;
  memcpy(v3, *(const void **)segment_metadata, *(_QWORD *)(segment_metadata + 8));
  memcpy(v4, *(const void **)(segment_metadata + 16), *(_QWORD *)(segment_metadata + 24));
  v6 = *(_QWORD *)(segment_metadata + 40);
  memcpy(v5, *(const void **)(segment_metadata + 32), *(_QWORD *)(segment_metadata + 40));
  emu_ctx->extra_size = v6;
  emu_ctx->UNK1 = 4096;
  emu_ctx->UNK2 = 0x8F00;
  return emu_ctx;
}
```

We can create a ida struct with the following content : 

```c
00000000 struct emu_ctx // sizeof=0x88
00000000 {
00000000     void* code;
00000008     void* data;
00000010     void* extra;
00000018     char *ptr_1;
00000020     __int64 extra_size;
00000028     void * check_flag_env;
00000030     char UNKB;
00000031     char UNKA;
00000032     char UNKC;
00000033     int UNK1;
00000037     int UNK2;
0000003B     int UNK3;
0000003F     int UNK4;
00000043     int UNK5;
00000047     int UNK6;
0000004B     char ptr_array[60];
00000087     char size_unk;
00000088 };
```

Note we assume first/2nd and third mmap is code/data/extra, when viewing segment data (first contains opcodode, second contains strings, and thirs contains extra data)

# Main Looop

Program seem to get a byte from extra, do some bittest on it, and select a handler based on the result. Also when a flag is always set to 1 when  some errors happens, exiting the loop.

We can assume that we are selecting the arch mode, and run the arch associated. 

We known now that : UNKB -> continue_emu flag

With errors we can have also a dump when emu exiting : 

```c
// Dumps the emulator state.
unsigned __int64 __fastcall dump_emu(emu_ctx *emu_ctx, char print_stack)
{
  int i; // ebp
  unsigned int sp_offset; // r12d
  const char *ascii; // rsi
  int value; // [rsp+Ch] [rbp-44h] BYREF
  unsigned __int64 v7; // [rsp+10h] [rbp-40h]

  v7 = __readfsqword(0x28u);
  printf(
    "  ---[ PC=0x%08x SP=0x%08x | A=0x%08x B=0x%08x C=0x%08x D=0x%08x\n",
    emu_ctx->PC,
    emu_ctx->SP,
    emu_ctx->A,
    emu_ctx->B,
    emu_ctx->C,
    emu_ctx->D);
  if ( print_stack )
  {
    puts("  ---[ STACK CONTENTS");
    for ( i = -8; i != 20; i += 4 )
    {
      sp_offset = emu_ctx->SP + i;
      if ( !(unsigned __int8)get_memory_emu_dword(emu_ctx, sp_offset, &value) )
        break;
      ascii = "  ";
      if ( emu_ctx->SP == sp_offset )
        ascii = "* ";
      printf("\t%s0x%08x  0x%08x\n", ascii, sp_offset, value);
    }
  }
  return v7 - __readfsqword(0x28u);
}
```

We can associate new emu registers in the emu_ctx struct. 

We can Then have more precise emulator in python: 

```py

class EmuCtx:
    def __init__(self):
        self.code = None
        self.data = None
        self.extra = None
        self.extra_size = 0
        self.PC = 0
        self.SP = 0
        self.dynamic = bytearray(60)
        self.size_unk = 0
        self.A = 0
        self.B = 0
        self.C = 0
        self.D = 0


def initialize_emu_ctx(self, seg_metadata):

    self.code = bytearray(0x1000)
    self.data = bytearray(0x1000)

    code_data,code_size = seg_metadata['code']
    data_data,data_size = seg_metadata['data']
    extra_data,extra_size = seg_metadata['extra']

    self.extra = bytearray(0x10000)
    self.extra_size = extra_size
    self.PC = 0x1000
    self.SP = 0x8F00

    self.code[:code_size] = code_data[:code_size]
    self.data[:data_size] = data_data[:data_size]
    self.extra[:extra_size] = extra_data[:extra_size]

class Emulator():
    def __init__(self, masm):
        self.masm = masm
        self.fd = open(masm, "rb")
        self._load_segments()
        self.ctx = EmuCtx()
        self.continue_emu = 1
        self.ctx.initialize_emu_ctx(self.segments_metadata)

    def get_arch_mode(self):
        pc = self.ctx.PC
        index = pc - 4089
        if ( pc - 4096 >= 0 ):
            index = pc - 4096

        data,_ = self.segments_metadata['extra']
        x = data[index >> 3]
        if pc == 0x1097: #patch for later
            return True
        
        return ((x >> (pc & 7)) & 1)

    def run_step(self):
        arch = self.get_arch_mode()   
        print(f"Arch={arch}")     
        if (not arch):
            self.run_step_arch1()
        elif (arch == 1):
            self.run_step_arch2()
        else:
            self.continue_emu = 0

    def run(self):
        print("[+] Emulator is running...")
        while self.continue_emu:
            self.run_step()
        print("[+] Emu has ended")
        self.ctx.dump_emu(print_stack=1)
```

# First Input

We have this input when starting program : 

```
-> % ./multiarch crackme.masm
[I] initializing multiarch emulator
[I] executing program
Welcome to the multiarch of madness! Let's see how well you understand it.
Challenge 1 - What's your favorite number?
```

Some debug show first used arch is ARCH1, so let's dig in.

Reversing the main arch1 function emulator is quite easy, the functions are straightforward. we assume the following functions are present :

- read_mem/write_mem
- get_memory_emu_dword
- push_dword_to_stack
- pop_dword_from_stack
- some syscall handling
- some misc functions
- handler for xor/add/mul/sub/...
- some flag setting for conditionnal jump

We can create them in the python emulator easily : 

```py
def run_step_arch1(self):
     
        value2 = 0

        x = self.ctx.read_mem(self.ctx.PC, 5)
        value1 = x[0]
        value2= int.from_bytes(x[1:3], byteorder="little")
        value3= int.from_bytes(x[1:], byteorder="little")


        print("--"*50)
        print(f"emu v1={hex(value1)}|v2={hex(value2)}|PC={hex(self.ctx.PC)}")
        #self.ctx.dump_emu(print_stack=1)
        
        if value1 <= 0x80:
            if value1 == 0x10:               
                self.ctx.push_byte_to_stack(value2)
                self.ctx.PC += 5
                return

            elif value1 == 0x20:                
                self.ctx.push_short_to_stack(value2)
                self.ctx.PC += 5
                return

            elif value1 == 0x30:
                self.ctx.push_dword_to_stack(value3)
                self.ctx.PC += 5
                return

            elif value1 == 0x40:
                x = int.from_bytes(self.ctx.read_mem(value2, 5), byteorder="little")
                self.ctx.push_dword_to_stack(x)
                self.ctx.PC += 5
                return 
            
            elif value1 == 0x41:
                raise Exception

            elif value1 == 0x50:
                _ = self.ctx.pop_dword_from_stack()
                self.ctx.PC += 5
                return

            elif value1 in (0x60, 0x61, 0x62, 0x63):
                v1 = self.ctx.pop_dword_from_stack()
                v2 = self.ctx.pop_dword_from_stack()

                op = {  0x60: lambda a, b: a + b,
                        0x61: lambda a, b: a - b,
                        0x62: lambda a, b: a ^ b,
                        0x63: lambda a, b: a & b,
                    }[value1]
                
                def get_op(v):
                    if v == 0x60:
                        return "+"
                    if v == 0x61:
                        return "-"
                    if v == 0x62:
                        return "^"
                    return "&"
                
                print(f"Push Stack OPERATION : {hex(value1)} -> {hex(v1)}{get_op(value1)}{hex(v2)} = {hex(op(v1,v2))}")

                self.ctx.push_dword_to_stack(op(v1, v2))
                self.ctx.PC += 5
                return

            elif value1 in (0x70, 0x71, 0x72):
                print(f"check_cond {hex(value1)}")
                cond = (self.ctx.flag & 1) != 0
                if (value1 == 0x71 and cond) or (value1 == 0x72 and not cond) or value1 == 0x70:
                    print(f"NEW PC SET -> {hex(value2)}")
                    self.ctx.PC = value2
                    return
                self.ctx.PC += 5
                return

            elif value1 == 0x80:
                v1 = self.ctx.pop_dword_from_stack()
                v2 = self.ctx.pop_dword_from_stack()
                self.ctx.set_flag(v1, v2)
                self.ctx.PC += 5
                return
                

            else:
                sys.stderr.write(f"[E] invalid StackVM instruction, pc=0x{self.ctx.PC:X} leader=0x{value1:X}\n")
                self.continue_emu = 0
                return 0

        # == Syscall handling ==
        elif value1 == 0xA0:
            if not self.ctx.check_syscall_specific():
                sys.stderr.write("[E] can't execute that syscall!\n")
                self.continue_emu = 0
                return            
            
            syscall_no = self.ctx.pop_byte_from_stack()
            print(f"syscall no -> {syscall_no}")

            if syscall_no == 0:
                self.ctx.push_dword_to_stack(self.ctx.read_user_input_dword())
                print("read_user_input_dword")
                self.ctx.PC += 5
                return
            elif syscall_no == 1:
                sys.stderr.write("[E] unsupported syscall!\n")
            elif syscall_no == 2:
                v1 = self.ctx.pop_dword_from_stack()
                v2 = self.ctx.pop_dword_from_stack()
                self.ctx.read_and_print(v1, v2)
                self.ctx.PC += 5
                return
                
            elif syscall_no == 3:
                v1 = self.ctx.pop_dword_from_stack()
                print(f"syscall srand({hex(v1)})")
                libc.srand(v1)
                self.ctx.PC += 5
                
            elif syscall_no == 4:
                low = libc.rand() & 0xFFFF
                high = libc.rand() << 16
                gen_val = (high | low) & 0xFFFFFFFF
                print(f"syscall rand()={hex(gen_val)}")
                self.ctx.push_dword_to_stack(gen_val)
                self.ctx.PC += 5
                return

            elif syscall_no == 5:
                print(b"CTF{test_flag}")
                self.ctx.PC += 5
                return
            
            elif syscall_no == 6:
                v1 = self.ctx.pop_dword_from_stack()
                raise Exception("todo")
                self.ctx.PC += 5
                return
            else:
                sys.stderr.write("[E] bad syscall!\n")

            self.continue_emu = 0
            return

        # == Halt instruction ==
        elif value1 == 0xFF:
            self.continue_emu = 0
            return

        # == Unknown instruction ==
        else:
            sys.stderr.write(f"[E] invalid StackVM instruction, pc=0x{self.ctx.PC:X} leader=0x{value1:X}\n")
            self.continue_emu = 0
            return
```

We can then start emulator and look at the dumped emu trace : 

```
Segment : 1 | offset=19 | size=357
Segment : 2 | offset=376 | size=336
Segment : 3 | offset=712 | size=45
[+] Emulator is running...
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x10|v2=0x4b|PC=0x1000
push_byte_to_stack -> 0x4b //push size of "Welcome to..." string
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x30|v2=0x2000|PC=0x1005
push_dword_to_stack -> 0x2000 // push string adress
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x10|v2=0x2|PC=0x100a
push_byte_to_stack -> 0x2 // push syscall no 2 for read_and_print syscall 
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0xa0|v2=0x0|PC=0x100f
check_syscall_specific
pop_byte_from_stack -> 0x2
syscall no -> 2
pop_dword_from_stack -> 0x2000
pop_dword_from_stack -> 0x4b
ReadAndPrint -> bytearray(b"Welcome to the multiarch of madness! Let\'s see how well you understand it.\n")
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x10|v2=0x2b|PC=0x1014
push_byte_to_stack -> 0x2b // push "Challenge1..." string size
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x30|v2=0x20ad|PC=0x1019
push_dword_to_stack -> 0x20ad // push string addr
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x10|v2=0x2|PC=0x101e
push_byte_to_stack -> 0x2 // push syscall no 2 for read and print
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0xa0|v2=0x0|PC=0x1023
check_syscall_specific
pop_byte_from_stack -> 0x2
syscall no -> 2
pop_dword_from_stack -> 0x20ad
pop_dword_from_stack -> 0x2b
ReadAndPrint -> bytearray(b"Challenge 1 - What\'s your favorite number? ")
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x10|v2=0x0|PC=0x1028
push_byte_to_stack -> 0x0 // push syscall no 0 : read_user_dword()
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0xa0|v2=0x0|PC=0x102d
check_syscall_specific
pop_byte_from_stack -> 0x0
syscall no -> 0
push_dword_to_stack -> 0x8f5a547a // that our input
read_user_input_dword
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x20|v2=0x1337|PC=0x1032
push_short_to_stack -> 0x1337 // push short
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x20|v2=0x539|PC=0x1037
push_short_to_stack -> 0x539 // push short
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x30|v2=0x5309|PC=0x103c
push_dword_to_stack -> 0x8675309 // push dword
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x62|v2=0x0|PC=0x1041
pop_dword_from_stack -> 0x8675309 // combine 2short -> dword
pop_dword_from_stack -> 0x13370539
Push Stack OPERATION : 0x62 -> 0x8675309^0x13370539 = 0x1b505630
push_dword_to_stack -> 0x1b505630 // created constant 
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x60|v2=0x0|PC=0x1046
pop_dword_from_stack -> 0x1b505630 // add last created constant with our input
pop_dword_from_stack -> 0x8f5a547a
Push Stack OPERATION : 0x60 -> 0x1b505630+0x8f5a547a = 0xaaaaaaaa
push_dword_to_stack -> 0xaaaaaaaa
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x30|v2=0xaaaa|PC=0x104b
push_dword_to_stack -> 0xaaaaaaaa
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x80|v2=0x0|PC=0x1050
pop_dword_from_stack -> 0xaaaaaaaa // compare previous op with 0xaaaaaaaa
pop_dword_from_stack -> 0xaaaaaaaa
set_flag -> 1 // set flag to 1 if A==B
Arch=0
mu v1=0x72|v2=0x110b|PC=0x1055
check_cond 0x72
```

I gave the good input for the trace, but the first input is quite simple when saving a trace : 

take a dword from user -> A
then 0x1b505630 + A  == 0xaaaaaaaa

We can easily deduce first input is 2405061754 (0x8f5a547a)

# Second input

For the second input, program switch to arch2

Arch 2 is a bit more complex to reverse as operations are more precise. 
The emulator introduce the usage of the registers A/B/C/D

arch2 keep the same functions with some additional content, but the core is the same (push/pop/read_mem/...)

Note that they use the popped value from opcode to write to the good registers

```c
set_flag(emu_ctx, *(&emu_ctx->A + ((val_1 >> 2) & 3)), *(&emu_ctx->A + (val_1 & 3)));
```

We can create the code in the python emulator: 

```py
def run_step_arch2(self):
        ctx = self.ctx
        print("--"*50)

        opcode1 = ctx.read_mem(ctx.PC, 1)[0]
        print(f"opcode={hex(opcode1)} | PC={hex(ctx.PC)}")
        
        ctx.PC += 1
        

        op_ext  = 0               # « v4 » dans le C ; nibbles d’extension
        opcode  = opcode1

        if (opcode1 >> 4) == 0xA:                 # 0xA0–0xAF
            op_ext = opcode1 & 0xF
            opcode = ctx.read_mem(ctx.PC, 1)[0]   # vrai opcode
            ctx.PC += 1

        if opcode == 0x00:                        # 0: arrêt net
            self.continue_emu = 0
            return


        if opcode == 0x01:
            if not ctx.check_syscall_specific():
                self.continue_emu = 0
                return

            sc_no = ctx.A & 0xFF
            print(f"[SYSCALL] no={sc_no}")

            if  sc_no == 0:                      # read dword -> A
                print("read_user_input_dword")
                ctx.A = ctx.read_user_input_dword()

            elif  sc_no == 1:                      # read dword -> A
                print("read_user_input_10char")
                ctx.read_user_input_(ctx.B, ctx.C)

            elif sc_no == 2:                      # read&print
                print("read_and_print")
                ctx.read_and_print(ctx.B, ctx.C)

            elif sc_no == 3:                      # srand(B)
                print(f"syscall srand({hex(ctx.B)})")
                libc.srand(ctx.B)

            elif sc_no == 4:                      # rand32 -> A
                print("rand()")
                low  = libc.rand() & 0xFFFF
                high = libc.rand() << 16
                ctx.A = (high | low) & 0xFFFFFFFF

            elif sc_no == 5:                      # flag !
                print(b"CTF{test_flag}")

            else:
                sys.stderr.write("[E] bad syscall!\n")
                self.continue_emu = 0
            return

        if opcode == 0x10:                        # push imm32
            imm = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            print(f"push imm32 : {hex(imm)}")
            ctx.push_dword_to_stack(imm)
            return


        if 0x11 <= opcode <= 0x14:                # push A/B/C/D
            reg_idx = opcode - 0x11
            print(f"push reg : {self.to_reg(reg_idx)} -> {hex(self._get_reg(reg_idx))}")
            ctx.push_dword_to_stack(self._get_reg(reg_idx))
            return

        if 0x15 <= opcode <= 0x18:                # pop  A/B/C/D
            reg_idx = opcode - 0x15
            val = ctx.pop_dword_from_stack()
            print(f"pop reg : {self.to_reg(reg_idx)} -> {hex(val)}")
            self._set_reg(reg_idx, val)
            return


        if (opcode >> 4) == 0x7:                  # 0x70-0x7F
            dst = (opcode >> 2) & 3
            src = opcode & 3
            print(f"set_flag : {hex(dst)}|{hex(src)}")
            ctx.set_flag(self._get_reg(dst), self._get_reg(src))
            return

        if (opcode >> 4) == 0x8:                  # 0x80-0x8F
            imm = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            dst = opcode & 3
            print(f"set_flag_reg : {hex(self._get_reg(dst))}|{hex(imm)}")
            if ctx.PC == 0x108d:
                ctx.set_flag(0x7331, 0x7331)
                return
            ctx.set_flag(self._get_reg(dst), imm)
            return


        if opcode == 0x20:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            dst = ((byte >> 4) - 1) & 3
            src = ((byte & 0xF) - 1) & 3
            res = (self._get_reg(dst) + self._get_reg(src)) & 0xFFFFFFFF
            print(f"0x20 ->{self.to_reg(dst)}={hex(res)}")
            self._set_reg(dst, res)
            return


        if opcode == 0x21:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            imm  = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            print(f"0X21 set SP={hex(imm+ctx.SP)}")
            ctx.SP = (ctx.SP + imm) & 0xFFFFFFFF
            return
            

        if opcode == 0x30:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            dst = ((byte >> 4) - 1) & 3
            src = ((byte & 0xF) - 1) & 3
            res = (self._get_reg(dst) - self._get_reg(src)) & 0xFFFFFFFF
            self._set_reg(dst, res)
            print(f"0X30 -> {self.to_reg(dst)}={hex(res)}")
            return


        if opcode == 0x31:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            imm  = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            high = byte >> 4
            if 1 <= high <= 4:                    # A…D
                dst = (high - 1) & 3
                self._set_reg(dst, (self._get_reg(dst) - imm) & 0xFFFFFFFF)
                print(f"set_reg {self.to_reg(dst)}={hex((self._get_reg(dst) - imm) & 0xFFFFFFFF)}")
                return
            if high == 5:                         # SP -= imm
                print(f"ctx.SP= {hex((ctx.SP - imm) & 0xFFFFFFFF)}")
                ctx.SP = (ctx.SP - imm) & 0xFFFFFFFF
                return
            
            self.continue_emu = 0
            return

        if opcode == 0x40:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            dst = ((byte >> 4) - 1) & 3
            src = ((byte & 0xF) - 1) & 3

            v1 = self._get_reg(dst)
            v2 = self._get_reg(src)
            r = v1 ^ v2

            print(f"XOR 0x40 -> {self.to_reg(dst)}= {hex(v1)} ^ {hex(v2)}={hex(r)}")

            self._set_reg(dst, r)
            return

        if opcode == 0x50:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            r1 = ((byte >> 4) - 1) & 3
            r2 = ((byte & 0xF) - 1) & 3
            prod = (self._get_reg(r1) * self._get_reg(r2)) & 0xFFFFFFFFFFFFFFFF
            ctx.A = prod & 0xFFFFFFFF
            ctx.D = (prod >> 32) & 0xFFFFFFFF
            print(f"MUL 0x50-> A={hex(ctx.A)}|D={hex(ctx.D)}")
            return

        if opcode == 0x51:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            imm  = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            r2   = (((byte >> 4) + 3) & 3)        # formule du binaire
            prod = (imm * self._get_reg(r2)) & 0xFFFFFFFFFFFFFFFF
            print(f"MUL 0x51-> {hex(imm)}*{hex(self._get_reg(r2))} = {hex(prod)}")
            ctx.A = prod & 0xFFFFFFFF
            ctx.D = (prod >> 32) & 0xFFFFFFFF
            print(f"MUL 0x51 A->{hex(ctx.A)} | D={hex(ctx.D)}")
            return

        if opcode == 0x60:
            target = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            ctx.push_dword_to_stack(ctx.PC)       # adresse de retour
            ctx.PC = target & 0xFFFFFFFF
            ctx.dump_emu(print_stack=True)
            print(f"call {hex(ctx.PC)}")
            return


        if opcode == 0x61:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            if ctx.patch_id == 0:
                ctx.SP = 0x00008EE2
                ctx.patch_id += 1
            else:
                ctx.SP = (ctx.SP + 4 * byte) & 0xFFFFFFFF
            ctx.PC = ctx.pop_dword_from_stack()
            print(f"ret {hex(ctx.PC)}")
            return


        if opcode in (0x62, 0x63, 0x64, 0x68):
            print(f"opcode JZ/JNZ/JN/JMP {opcode}")
            ctx.cpt += 1
            #ctx.dump_emu(print_stack=True)
            if ctx.cpt == 19:
                print(f"TAKE BRANCH2")
                target = ctx.get_memory_emu_dword(ctx.PC)
                ctx.PC = target & 0xFFFFFFFF
                return
            taken = False
            if opcode == 0x62:                    # JZ  (flag bit0 == 1)
                taken = (ctx.flag & 1) != 0
            elif opcode == 0x63:                  # JNZ (flag bit0 == 0)
                taken = (ctx.flag & 1) == 0
            elif opcode == 0x64:                  # JN  (flag bit1 == 1)
                taken = (ctx.flag & 2) != 0
            elif opcode == 0x68:                  # JMP inconditionnel
                taken = True

            if taken:
                target = ctx.get_memory_emu_dword(ctx.PC)
                ctx.PC = target & 0xFFFFFFFF
                print(f"TAKEN BRANCH | new pc = {hex(ctx.PC)}")
            else:
                print(f"NO TAKE BRANCH")
                ctx.PC += 4
            return

        if opcode >= 0xC0:
            dst_code = (opcode >> 3) & 7
            src_code = opcode & 7
            src_mode_indirect = (opcode & 4) == 0      # bit 2 == 0
            ext_low2  = op_ext & 3                     # v10  → src déréf
            ext_high  = op_ext >> 2                    # v4>>2→ dst [Reg]

            if src_mode_indirect:
                # src = Reg
                src_val = self._get_reg(src_code)
                if ext_low2:                           # [Reg]
                    src_val = ctx.get_memory_emu_dword(src_val)
            else:
                # src = variantes 4 / 5 / 6
                if   src_code == 4:                    # src = [imm32]
                    addr    = ctx.get_memory_emu_dword(ctx.PC); ctx.PC += 4
                    src_val = ctx.get_memory_emu_dword(addr)
                elif src_code == 5:                    # src = imm32
                    src_val = ctx.get_memory_emu_dword(ctx.PC); ctx.PC += 4
                elif src_code == 6:                    # src = SP / [SP]
                    src_val = ctx.SP
                    if ext_low2:
                        src_val = ctx.get_memory_emu_dword(src_val)
                else:
                    self.continue_emu = 0
                    return
                if ext_low2:                           # déréf interdit ici
                    self.continue_emu = 0
                    return

            if ext_high:                               # dst = [RegDst]
                if dst_code >= 4:                      # RegDst doit être A-D
                    self.continue_emu = 0
                    return
                addr = self._get_reg(dst_code)
                ctx.write_to_mem_dword(addr, src_val)
                print(f"opcode EH {hex(addr)}={hex(src_val)}")
                return

            if (opcode & 0x20) == 0:                   # dst = RegDst
                self._set_reg(dst_code, src_val)
                print(f"_set_reg 0X20 {self.to_reg(dst_code)}={hex(src_val)}")
                return

            if dst_code != 4 or src_code == 6:
                ctx.exec_failed = 1
                self.continue_emu = 0
                return
            addr = ctx.get_memory_emu_dword(ctx.PC); ctx.PC += 4
            ctx.write_to_mem_dword(addr, src_val)
            print(f"opcode2 {hex(addr)}={hex(src_val)}")

            return

        sys.stderr.write(f"[E] invalid RegVM instruction, pc=0x{ctx.PC - 1:08X} leader=0x{opcode:02X}\n")
        self.continue_emu = 0
        
    def _get_reg(self, idx: int) -> int:
        if idx == 0:
            return self.ctx.A
        if idx == 1:
            return self.ctx.B
        if idx == 2:
            return self.ctx.C
        if idx == 3:
            return self.ctx.D
        if idx == 4:
            return self.ctx.SP
        raise ValueError(f"Reg index out of range: {idx}")

    def _set_reg(self, idx: int, value: int) -> None:
        value &= 0xFFFFFFFF
        if idx == 0:
            self.ctx.A = value
        elif idx == 1:
            self.ctx.B = value
        elif idx == 2:
            self.ctx.C = value
        elif idx == 3:
            self.ctx.D = value
        elif idx == 4:
            self.ctx.SP = value
        else:
            raise ValueError(f"Reg index out of range: {idx}")

    def to_reg(self, idx):
        if idx == 0:
            return "A"
        elif idx == 1:
            return "B"
        elif idx == 2:
            return "C"
        elif idx == 3:
            return "D"
        elif idx == 4:
            return "SP"
        else:
            raise ValueError(f"Reg index out of range: {idx}")

```

There is some opcode i din't reverse in details as i can copy the decompiled outputs and cast them in python. my goal is mainly to analyze the dumped trace to understand the math operations behing the emulator.

I could also run the program with gdb, script some handlers and generate a trace. 
I have done that to dump some xor/mul operations in input2:

```py
import gdb

gdb.execute("file multiarch")
gdb.execute("d")

def to_int(gdb_v:gdb.Value):
    return int(gdb_v.cast(gdb.lookup_type('long long')))

class Dumper(gdb.Breakpoint):
    
    def __init__(self, bp, opcode):
        super().__init__(bp)
        self.opcode = opcode
    
    def stop(self):
        if self.opcode == 1:
            rax = to_int(gdb.parse_and_eval("(uint64_t *)$rax"))
            rdx = to_int(gdb.parse_and_eval("(uint64_t *)$rdx"))
            result =  rax * rdx
            print(f"{hex(rax)}*{hex(rdx)}={hex(result)}")
            return False

        elif self.opcode == 2:
            eax = to_int(gdb.parse_and_eval("(uint32_t *)$eax"))
            addr = to_int(gdb.parse_and_eval("$rbx + $rdx * 4 + 0x3B"))
            v1 = to_int(gdb.parse_and_eval(f"(uint32_t)*(uint32_t *)({addr})"))
            print(f"{hex(eax)} ^{hex(v1)}={hex(eax ^ v1 )}")

            return False
    

bp2 = Dumper("*0x0005555555566CE", 2)
bp3 = Dumper("*0x00005555555567F8", 1)

gdb.execute("r crackme.masm")
```

This code will be used to review some math operations during stage2
We can run the emulator to get the new trace : 

```
... trace part1
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xc5 | PC=0x105a
_set_reg 0X20 A=0x2 // syscall no 2 for read_and print
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xcd | PC=0x105f
_set_reg 0X20 B=0x20d8 // "Challenge 2" addr
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xd5 | PC=0x1064
_set_reg 0X20 C=0x1e // string size
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x1 | PC=0x1069
check_syscall_specific
[SYSCALL] no=2
read_and_print
ReadAndPrint -> bytearray(b'Challenge 2 - Tell me a joke: ')
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x31 | PC=0x106a
ctx.SP= 0x8ee6 // set new SP
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xce | PC=0x1070
_set_reg 0X20 B=0x8ee6 
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x12 | PC=0x1071
push reg : B -> 0x8ee6
push_dword_to_stack -> 0x8ee6
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xd5 | PC=0x1072
_set_reg 0X20 C=0x20 // push size 0X20 => user_input_len
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xc5 | PC=0x1077
_set_reg 0X20 A=0x1 // syscall no 1 : read_user_input(size)
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x1 | PC=0x107c
check_syscall_specific
[SYSCALL] no=1
read_user_input_
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x15 | PC=0x107d
pop_dword_from_stack -> 0x8ee6
pop reg : A -> 0x8ee6
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xcd | PC=0x107e
_set_reg 0X20 B=0x20
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x60 | PC=0x1083
push_dword_to_stack -> 0x1088 // push current PC before call
  ---[ PC=0x0000111C SP=0x00008EE2 | A=0x00008EE6 B=0x00000020 C=0x00000020 D=0x00000000
  ---[ STACK CONTENTS
	  0x00008EDA  0x00000000
	  0x00008EDE  0x00000000
	* 0x00008EE2  0x00001088 // return adress
	  0x00008EE6  0x2E203320 // our user input is on stack
	  0x00008EEA  0x2E202020
	  0x00008EEE  0x41414141 
	  0x00008EF2  0x41414141
call 0x111c // call func
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xd0 | PC=0x111c
_set_reg 0X20 C=0x8ee6
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x20 | PC=0x111d
0x20 ->A=0x8f06
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x11 | PC=0x111f
push reg : A -> 0x8f06
push_dword_to_stack -> 0x8f06
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xcd | PC=0x1120
_set_reg 0X20 B=0x0
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xa1 | PC=0x1125
_set_reg 0X20 D=0x2e203320 // first dword of our input
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x51 | PC=0x1127
MUL 0x51-> 0xcafebabe*0x2e203320 = 0x24934def9acb31c0 // multiply our dword by 0xcafebabe
MUL 0x51 A->0x9acb31c0 | D=0x24934def // take lower32bits of mul
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x40 | PC=0x112d
XOR 0x40 -> B= 0x0 ^ 0x24934def=0x24934def // xor with a accumulator
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x15 | PC=0x112f
pop_dword_from_stack -> 0x8f06
pop reg : A -> 0x8f06
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x11 | PC=0x1130
push reg : A -> 0x8f06
push_dword_to_stack -> 0x8f06
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x72 | PC=0x1131
set_flag : 0x0|0x2
set_flag -> 0
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x62 | PC=0x1132
opcode JZ/JNZ/JN/JMP 98
NO TAKE BRANCH
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x21 | PC=0x1137
0X21 set SP=0x8ee2
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x68 | PC=0x113d
opcode JZ/JNZ/JN/JMP 104
TAKEN BRANCH | new pc = 0x1125 // while (dword != null)
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xa1 | PC=0x1125
_set_reg 0X20 D=0x2e203320
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x51 | PC=0x1127
MUL 0x51-> 0xcafebabe*0x2e203320 = 0x24934def9acb31c0
MUL 0x51 A->0x
```

This xor loop until dword is finish. 

The loop is a simple xor accumulator
it take a dword for user input (32char => 8 iteration), multiply with 0xcafebabe , take lower 32bits of mul, then xor with previous acu.

So we have : 

((X1 x 0xcafebabe)>>32 ^ 0) ^ ((X2 x 0xcafebabe)>>32) ^ ... = Y

when returning from call, we have a check condition / set_flag with constant 0x7331

So me must find a 32input that return acu=0x7331 after the 8xor loops.

After hardcore personnal reflexion, uh chat gpt, the input that validate the second question can be : " 3 .   .AAAAAAAABBBBBBBBCCCCCCCC" => this return 0x7331 and pass the check.

# Third input

```
----------------------------------------------------------------------------------------------------
opcode=0x1 | PC=0x10ab
check_syscall_specific
[SYSCALL] no=0
read_user_input_dword
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xc8 | PC=0x10ac
_set_reg 0X20 B=0x2b6043c
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xc5 | PC=0x10ad
_set_reg 0X20 A=0x3
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x1 | PC=0x10b2
check_syscall_specific
[SYSCALL] no=3
syscall srand(0x2b6043c)
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xd5 | PC=0x10b3
_set_reg 0X20 C=0x0
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x60 | PC=0x10b8
push_dword_to_stack -> 0x10bd
  ---[ PC=0x00001145 SP=0x00008EE2 | A=0x00000003 B=0x02B6043C C=0x00000000 D=0x24934DEF
  ---[ STACK CONTENTS
	  0x00008EDA  0x02000000
	  0x00008EDE  0x000020F6
	* 0x00008EE2  0x000010BD
	  0x00008EE6  0x2E203320
	  0x00008EEA  0x2E202020
	  0x00008EEE  0x41414141
	  0x00008EF2  0x41414141
call 0x1145
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0xc5 | PC=0x1145
_set_reg 0X20 A=0x133700
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x10|v2=0x4|PC=0x114a
push_byte_to_stack -> 0x4
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0xa0|v2=0x0|PC=0x114f
check_syscall_specific
pop_byte_from_stack -> 0x4
syscall no -> 4
syscall rand()=0x7a213a1c
push_dword_to_stack -> 0x7a213a1c
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x16 | PC=0x1154
pop_dword_from_stack -> 0x7a213a1c
pop reg : B -> 0x7a213a1c
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x40 | PC=0x1155
XOR 0x40 -> A= 0x133700 ^ 0x7a213a1c=0x7a320d1c
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x11 | PC=0x1157
push reg : A -> 0x7a320d1c
push_dword_to_stack -> 0x7a320d1c
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x30|v2=0xf2f2|PC=0x1158
push_dword_to_stack -> 0xf2f2f2f2
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x62|v2=0x0|PC=0x115d
pop_dword_from_stack -> 0xf2f2f2f2
pop_dword_from_stack -> 0x7a320d1c
Push Stack OPERATION : 0x62 -> 0xf2f2f2f2^0x7a320d1c = 0x88c0ffee
push_dword_to_stack -> 0x88c0ffee
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x15 | PC=0x1162
pop_dword_from_stack -> 0x88c0ffee
pop reg : A -> 0x88c0ffee
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x61 | PC=0x1163
pop_dword_from_stack -> 0x10bd
ret 0x10bd
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x10 | PC=0x10bd
push imm32 : 0xffffff
push_dword_to_stack -> 0xffffff
Arch=1
----------------------------------------------------------------------------------------------------
opcode=0x11 | PC=0x10c2
push reg : A -> 0x88c0ffee
push_dword_to_stack -> 0x88c0ffee
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x63|v2=0x0|PC=0x10c3
pop_dword_from_stack -> 0x88c0ffee
pop_dword_from_stack -> 0xffffff
Push Stack OPERATION : 0x63 -> 0x88c0ffee&0xffffff = 0xc0ffee
push_dword_to_stack -> 0xc0ffee
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x30|v2=0xffee|PC=0x10c8
push_dword_to_stack -> 0xc0ffee
Arch=0
----------------------------------------------------------------------------------------------------
emu v1=0x80|v2=0x0|PC=0x10cd
pop_dword_from_stack -> 0xc0ffee
pop_dword_from_stack -> 0xc0ffee
set_flag -> 1
Arch=0
```

Last question is a switch mode between arch 1 and arch2. 
When reviewing the trace, it ask a dword for user, then srand(user_dword) and do some rand().

it then xor some generated random int, mask it and some others operations. It check if computed data equals to another hardcoded data.

We can resume this as :

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main(void)
{
    const uint32_t XOR1   = 0x00133700;
    const uint32_t XOR2   = 0xF2F2F2F2;
    const uint32_t TARGET = 0x00C0FFEE;
    const uint32_t MASK   = 0x00FFFFFF;

    for (uint32_t seed = 0; ; ++seed) {
        srand(seed);
        uint32_t val = (uint16_t)rand();             // HIGH
        val |= ((uint32_t)(rand())) << 16;
        
        uint32_t result = (val ^ XOR1 ^ XOR2) & MASK;
        if (result == TARGET) {
            printf("[+] Seed trouvé : 0x%08X (%u)\n", seed, seed);
            
            printf("    gen_val = 0x%08X\n", val);
            printf("    result =  0x%06X\n", result);
            return 0;
        }

        if (seed == 0xFFFFFFFF) {
            puts("[-] Aucun seed trouvé.");
            return 1;
        }
    }
}
```

This code return `45483068` after 3minutes, which validate last question! 

We got the flag (stored in a env on remote server) : `CTF{st3ph3n_str4ng3_0nly_us3s_m1ps_wh4t_a_n00b}
`

a nice not so hard chall but long chall about reversing emulators and analysing trace. 

Full emulator : 
```py
import os
import struct
import sys
from io import BytesIO

import ctypes
import mmap
libc = ctypes.CDLL("libc.so.6")

class EmuCtx:
    def __init__(self):
        self.code = None
        self.data = None
        self.mmap3 = None
        self.extra = None
        self.extra_size = 0
        self.PC = 0
        self.SP = 0
        self.dynamic = bytearray(60)
        self.size_unk = 0
        self.A = 0
        self.B = 0
        self.C = 0
        self.D = 0
        self.flag = 0
        self.execute_as_system = 0
        self.cpt = 0
        self.patch_id = 0
        self.first_time=0

    def read_mem(self, offset, size):
        end = offset + size
        # code segment: 0x1000–0x1FFF
        if 0x1000 <= offset <= 0x1FFF and end <= 0x2000:
            #print(f"read code {hex(offset)}:{size} -> {self.code[offset-0x1000:offset-0x1000+size]}")
            return self.code[offset - 0x1000:end - 0x1000]

        # data segment: 0x2000–0x2FFF
        if 0x2000 <= offset <= 0x2FFF and end <= 0x3000:
            #print(f"read data {hex(offset)}:{size} -> {self.data[offset-0x2000:offset-0x2000+size]}")
            return self.data[offset - 0x2000:end - 0x2000]

        # extra segment: 0x8000–0x8FFF
        if 0x8000 <= offset <= 0x8FFF and end <= 0x9000:
            #print(f"read extra {hex(offset)}:{size} -> {self.extra[offset-0x8000:offset-0x8000+size]}")
            return self.extra[offset-0x8000:end - 0x8000]
        
        for entry in self.dynamic[:self.size_unk]:
            base = entry["base"]
            if base <= offset < base + 512 and end <= base + 512:
                offset = offset - base
                return entry["ptr"][offset:offset + size if size else None]

        raise Exception("Invalid readmem")
    
    def set_flag(self, a2, a3):
        diff = a2 - a3
        flag = 2 * ((diff >> 31) & 1)  # sets flag = 2 if negative
        if diff == 0:
            flag = 1  # overwrite if result is zero
        print(f"set_flag -> {flag}")
        self.flag = flag | 0x4     # always OR with 0x4

    def write_to_mem_dword(self, addr: int, value: int) -> bool:
        self.write_mem(addr, value & 0xFFFFFFFF, 4)

    def write_mem(self, offset, data, size, format=int):
        end = offset + size
        #print(f"write_mem {hex(offset)} = {data}|{size}")
        if 0x1000 <= offset <= 0x1FFF and end <= 0x2000:
            if format == bytes:
                self.code[offset - 0x1000:end - 0x1000] = data
            else:
                self.code[offset - 0x1000:end - 0x1000] = data.to_bytes(size, byteorder="little")
            return

        # data segment: 0x2000–0x2FFF
        if 0x2000 <= offset <= 0x2FFF and end <= 0x3000:
            if format == bytes:
                self.data[offset - 0x2000:end - 0x2000] = data
            else:
                self.data[offset - 0x2000:end - 0x2000] = data.to_bytes(size, byteorder="little")
            return

        # extra segment: 0x8000–0x8FFF
        if 0x8000 <= offset <= 0x8FFF and end <= 0x9000:
            if format == bytes:
                self.extra[offset - 0x8000:end - 0x8000] = data
            else:
                self.extra[offset - 0x8000:end - 0x8000] = data.to_bytes(size, byteorder="little")
            return

        raise Exception("todo ptr_array")
    
    def read_user_input_dword(self):
        if self.first_time==0:
            self.first_time +=1
            return 0x8f5a547a
        else:
            return 45483068
    
    def read_user_input_(self, offset, size):
        x = b" 3 .   .AAAAAAAABBBBBBBBCCCCCCCC"
        self.write_mem(offset, x, size, format=bytes)
    
    def read_and_print(self, v1, v2):
        x = self.read_mem(v1, v2)
        print(f"ReadAndPrint -> {x}")

    def check_syscall_specific(self):
        print("check_syscall_specific")
        syscall_no = self.A & 0xFF  # LOBYTE equivalent
        if syscall_no <= 5:
            return True
        elif syscall_no == 6:
            return self.execute_as_system != 0
        else:
            sys.stderr.write(f"[E] invalid syscall! 0x{syscall_no:X}\n")
            return False

    def get_memory_emu_dword(self, offset):
        return int.from_bytes(self.read_mem(offset, 4), byteorder="little")
    
    def push_byte_to_stack(self, data):
        x = self.SP - 1
        self.SP = x
        print(f"push_byte_to_stack -> {hex(data)}")
        self.write_mem(x, data, 1)

    def push_short_to_stack(self, data):
        x = self.SP - 2
        self.SP = x
        print(f"push_short_to_stack -> {hex(data)}")
        self.write_mem(x, data, 2)

    def push_dword_to_stack(self, data):
        x = self.SP - 4
        self.SP = x
        print(f"push_dword_to_stack -> {hex(data)}")
        self.write_mem(x, data, 4)

    def pop_byte_from_stack(self):
        r = self.read_mem(self.SP, 1)
        self.SP += 1
        x = int.from_bytes(r, byteorder="little")
        print(f"pop_byte_from_stack -> {hex(x)}")
        return x
    
    def pop_short_from_stack(self):
        r = self.read_mem(self.SP, 2)
        self.SP += 2
        x = int.from_bytes(r, byteorder="little")
        print(f"pop_short_from_stack -> {hex(x)}")
        return x
    
    def pop_dword_from_stack(self):
        r = self.read_mem(self.SP, 4)
        self.SP += 4
        x = int.from_bytes(r, byteorder="little")
        print(f"pop_dword_from_stack -> {hex(x)}")
        return x

    def initialize_emu_ctx(self, seg_metadata):

        self.code = bytearray(0x1000)
        self.data = bytearray(0x1000)

        code_data,code_size = seg_metadata['code']
        data_data,data_size = seg_metadata['data']
        extra_data,extra_size = seg_metadata['extra']

        self.extra = bytearray(0x10000)
        self.extra_size = extra_size
        self.PC = 0x1000
        self.SP = 0x8F00

        self.code[:code_size] = code_data[:code_size]
        self.data[:data_size] = data_data[:data_size]
        self.extra[:extra_size] = extra_data[:extra_size]

    def dump_emu(self, print_stack=False):
        print(
            f"  ---[ PC=0x{self.PC:08X} SP=0x{self.SP:08X} | "
            f"A=0x{self.A:08X} B=0x{self.B:08X} "
            f"C=0x{self.C:08X} D=0x{self.D:08X}"
        )

        if print_stack:
            print("  ---[ STACK CONTENTS")
            for i in range(-8, 20, 4):
                sp_offset = self.SP + i
                value = self.get_memory_emu_dword(sp_offset)
                prefix = "* " if sp_offset == self.SP else "  "
                print(f"\t{prefix}0x{sp_offset:08X}  0x{value:08X}")



class Emulator():
    def __init__(self, masm):
        self.masm = masm
        self.fd = open(masm, "rb")
        self._load_segments()
        self.ctx = EmuCtx()
        self.continue_emu = 1
        self.ctx.initialize_emu_ctx(self.segments_metadata)

    def __del__(self):
        self.fd.close()

    def _load_segments(self):
        if self.fd.read(4) != b"MASM":
            sys.stderr.write("[E] bad magic\n")
            sys.exit()

        self.segments_metadata = {}
        self.fd.seek(4)

        self.read_segments(4)
        self.read_segments(9)
        self.read_segments(14)


    def read_segments(self, size_offset):
        self.fd.seek(size_offset)
        segment_type_raw = self.fd.read(1)
        segment_type = struct.unpack("B", segment_type_raw)[0]
        offset_raw = self.fd.read(2)
        offset = struct.unpack("<H", offset_raw)[0]
        size_raw = self.fd.read(2)
        size = struct.unpack("<H", size_raw)[0]
        
        self.fd.seek(offset)
        data = self.fd.read(size)

        print(f"Segment : {segment_type} | offset={offset} | size={size}")
           
        if segment_type == 1:
            self.segments_metadata['code'] = (data, size)
        elif segment_type == 2:
            self.segments_metadata['data'] = (data, size)
        elif segment_type == 3:
            self.segments_metadata['extra'] = (data, size)
        else:
            sys.stderr.write(f"[E] invalid segment type: {segment_type}\n")
            return False

        return True
    
    def get_arch_mode(self):
        pc = self.ctx.PC
        index = pc - 4089
        if ( pc - 4096 >= 0 ):
            index = pc - 4096

        data,_ = self.segments_metadata['extra']
        x = data[index >> 3]
        #print(x, x>0, hex(pc))
        if pc == 0x1097:
            return True
        
        return ((x >> (pc & 7)) & 1)

    def run_step_arch1(self):
     
        value2 = 0

        x = self.ctx.read_mem(self.ctx.PC, 5)
        value1 = x[0]
        value2= int.from_bytes(x[1:3], byteorder="little")
        value3= int.from_bytes(x[1:], byteorder="little")


        print("--"*50)
        print(f"emu v1={hex(value1)}|v2={hex(value2)}|PC={hex(self.ctx.PC)}")
        #self.ctx.dump_emu(print_stack=1)
        
        if value1 <= 0x80:
            if value1 == 0x10:               
                self.ctx.push_byte_to_stack(value2)
                self.ctx.PC += 5
                return

            elif value1 == 0x20:                
                self.ctx.push_short_to_stack(value2)
                self.ctx.PC += 5
                return

            elif value1 == 0x30:
                self.ctx.push_dword_to_stack(value3)
                self.ctx.PC += 5
                return

            elif value1 == 0x40:
                x = int.from_bytes(self.ctx.read_mem(value2, 5), byteorder="little")
                self.ctx.push_dword_to_stack(x)
                self.ctx.PC += 5
                return 
            
            elif value1 == 0x41:
                raise Exception

            elif value1 == 0x50:
                _ = self.ctx.pop_dword_from_stack()
                self.ctx.PC += 5
                return

            elif value1 in (0x60, 0x61, 0x62, 0x63):
                v1 = self.ctx.pop_dword_from_stack()
                v2 = self.ctx.pop_dword_from_stack()

                op = {  0x60: lambda a, b: a + b,
                        0x61: lambda a, b: a - b,
                        0x62: lambda a, b: a ^ b,
                        0x63: lambda a, b: a & b,
                    }[value1]
                
                def get_op(v):
                    if v == 0x60:
                        return "+"
                    if v == 0x61:
                        return "-"
                    if v == 0x62:
                        return "^"
                    return "&"
                
                print(f"Push Stack OPERATION : {hex(value1)} -> {hex(v1)}{get_op(value1)}{hex(v2)} = {hex(op(v1,v2))}")

                self.ctx.push_dword_to_stack(op(v1, v2))
                self.ctx.PC += 5
                return

            elif value1 in (0x70, 0x71, 0x72):
                print(f"check_cond {hex(value1)}")
                cond = (self.ctx.flag & 1) != 0
                if (value1 == 0x71 and cond) or (value1 == 0x72 and not cond) or value1 == 0x70:
                    print(f"NEW PC SET -> {hex(value2)}")
                    self.ctx.PC = value2
                    return
                self.ctx.PC += 5
                return

            elif value1 == 0x80:
                v1 = self.ctx.pop_dword_from_stack()
                v2 = self.ctx.pop_dword_from_stack()
                self.ctx.set_flag(v1, v2)
                self.ctx.PC += 5
                return
                

            else:
                sys.stderr.write(f"[E] invalid StackVM instruction, pc=0x{self.ctx.PC:X} leader=0x{value1:X}\n")
                self.continue_emu = 0
                return 0

        # == Syscall handling ==
        elif value1 == 0xA0:
            if not self.ctx.check_syscall_specific():
                sys.stderr.write("[E] can't execute that syscall!\n")
                self.continue_emu = 0
                return            
            
            syscall_no = self.ctx.pop_byte_from_stack()
            print(f"syscall no -> {syscall_no}")

            if syscall_no == 0:
                self.ctx.push_dword_to_stack(self.ctx.read_user_input_dword())
                print("read_user_input_dword")
                self.ctx.PC += 5
                return
            elif syscall_no == 1:
                sys.stderr.write("[E] unsupported syscall!\n")
            elif syscall_no == 2:
                v1 = self.ctx.pop_dword_from_stack()
                v2 = self.ctx.pop_dword_from_stack()
                self.ctx.read_and_print(v1, v2)
                self.ctx.PC += 5
                return
                
            elif syscall_no == 3:
                v1 = self.ctx.pop_dword_from_stack()
                print(f"syscall srand({hex(v1)})")
                libc.srand(v1)
                self.ctx.PC += 5
                
            elif syscall_no == 4:
                low = libc.rand() & 0xFFFF
                high = libc.rand() << 16
                gen_val = (high | low) & 0xFFFFFFFF
                print(f"syscall rand()={hex(gen_val)}")
                self.ctx.push_dword_to_stack(gen_val)
                self.ctx.PC += 5
                return

            elif syscall_no == 5:
                print(b"CTF{test_flag}")
                self.ctx.PC += 5
                return
            
            elif syscall_no == 6:
                v1 = self.ctx.pop_dword_from_stack()
                raise Exception("todo")
                self.ctx.PC += 5
                return
            else:
                sys.stderr.write("[E] bad syscall!\n")

            self.continue_emu = 0
            return

        # == Halt instruction ==
        elif value1 == 0xFF:
            self.continue_emu = 0
            return

        # == Unknown instruction ==
        else:
            sys.stderr.write(f"[E] invalid StackVM instruction, pc=0x{self.ctx.PC:X} leader=0x{value1:X}\n")
            self.continue_emu = 0
            return

    
    def run_step_arch2(self):
        ctx = self.ctx
        print("--"*50)
        # ------------------------------------------------------ FETCH --- #
        opcode1 = ctx.read_mem(ctx.PC, 1)[0]
        print(f"opcode={hex(opcode1)} | PC={hex(ctx.PC)}")
        
        ctx.PC += 1
        

        op_ext  = 0               # « v4 » dans le C ; nibbles d’extension
        opcode  = opcode1

        # --------------------------- pré-décodage 0xAx? à deux octets --- #
        if (opcode1 >> 4) == 0xA:                 # 0xA0–0xAF
            op_ext = opcode1 & 0xF
            opcode = ctx.read_mem(ctx.PC, 1)[0]   # vrai opcode
            ctx.PC += 1

        # ------------------------------------------------------ HALT ---- #
        if opcode == 0x00:                        # 0: arrêt net
            self.continue_emu = 0
            return

        # --------------------------------------------------- SYSCALL ---- #
        if opcode == 0x01:
            if not ctx.check_syscall_specific():
                self.continue_emu = 0
                return

            sc_no = ctx.A & 0xFF
            print(f"[SYSCALL] no={sc_no}")

            if  sc_no == 0:                      # read dword -> A
                print("read_user_input_dword")
                ctx.A = ctx.read_user_input_dword()

            elif  sc_no == 1:                      # read dword -> A
                print("read_user_input_10char")
                ctx.read_user_input_(ctx.B, ctx.C)

            elif sc_no == 2:                      # read&print
                print("read_and_print")
                ctx.read_and_print(ctx.B, ctx.C)

            elif sc_no == 3:                      # srand(B)
                print(f"syscall srand({hex(ctx.B)})")
                libc.srand(ctx.B)

            elif sc_no == 4:                      # rand32 -> A
                print("rand()")
                low  = libc.rand() & 0xFFFF
                high = libc.rand() << 16
                ctx.A = (high | low) & 0xFFFFFFFF

            elif sc_no == 5:                      # flag !
                print(b"CTF{test_flag}")

            else:
                sys.stderr.write("[E] bad syscall!\n")
                self.continue_emu = 0
            return

        # ---------------------------------------------------- PUSH IMM -- #
        if opcode == 0x10:                        # push imm32
            imm = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            print(f"push imm32 : {hex(imm)}")
            ctx.push_dword_to_stack(imm)
            return

        # ---------------------------------------------- PUSH REG 0x11-14 #
        if 0x11 <= opcode <= 0x14:                # push A/B/C/D
            reg_idx = opcode - 0x11
            print(f"push reg : {self.to_reg(reg_idx)} -> {hex(self._get_reg(reg_idx))}")
            ctx.push_dword_to_stack(self._get_reg(reg_idx))
            return

        # ---------------------------------------------- POP  REG 0x15-18 #
        if 0x15 <= opcode <= 0x18:                # pop  A/B/C/D
            reg_idx = opcode - 0x15
            val = ctx.pop_dword_from_stack()
            print(f"pop reg : {self.to_reg(reg_idx)} -> {hex(val)}")
            self._set_reg(reg_idx, val)
            return

        # ---------------------------------------------------- SET_FLAG -- #
        if (opcode >> 4) == 0x7:                  # 0x70-0x7F
            dst = (opcode >> 2) & 3
            src = opcode & 3
            print(f"set_flag : {hex(dst)}|{hex(src)}")
            ctx.set_flag(self._get_reg(dst), self._get_reg(src))
            return

        # --------------------------------------------- SET_FLAG IMM 0x8x #
        if (opcode >> 4) == 0x8:                  # 0x80-0x8F
            imm = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            dst = opcode & 3
            print(f"set_flag_reg : {hex(self._get_reg(dst))}|{hex(imm)}")
            if ctx.PC == 0x108d:
                ctx.set_flag(0x7331, 0x7331)
                return
            ctx.set_flag(self._get_reg(dst), imm)
            return

        # -------------------------------------------------- ADD 0x20 ---- #
        if opcode == 0x20:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            dst = ((byte >> 4) - 1) & 3
            src = ((byte & 0xF) - 1) & 3
            res = (self._get_reg(dst) + self._get_reg(src)) & 0xFFFFFFFF
            print(f"0x20 ->{self.to_reg(dst)}={hex(res)}")
            self._set_reg(dst, res)
            return

        # ---------------------------------------------- ADD IMM  -> SP -- #
        if opcode == 0x21:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            imm  = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            print(f"0X21 set SP={hex(imm+ctx.SP)}")
            ctx.SP = (ctx.SP + imm) & 0xFFFFFFFF
            return
            

        # -------------------------------------------------- SUB 0x30 ---- #
        if opcode == 0x30:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            dst = ((byte >> 4) - 1) & 3
            src = ((byte & 0xF) - 1) & 3
            res = (self._get_reg(dst) - self._get_reg(src)) & 0xFFFFFFFF
            self._set_reg(dst, res)
            print(f"0X30 -> {self.to_reg(dst)}={hex(res)}")
            return

        # ---------------------------------------------- SUB IMM / SP 31 -- #
        if opcode == 0x31:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            imm  = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            high = byte >> 4
            if 1 <= high <= 4:                    # A…D
                dst = (high - 1) & 3
                self._set_reg(dst, (self._get_reg(dst) - imm) & 0xFFFFFFFF)
                print(f"set_reg {self.to_reg(dst)}={hex((self._get_reg(dst) - imm) & 0xFFFFFFFF)}")
                return
            if high == 5:                         # SP -= imm
                print(f"ctx.SP= {hex((ctx.SP - imm) & 0xFFFFFFFF)}")
                ctx.SP = (ctx.SP - imm) & 0xFFFFFFFF
                return
            
            self.continue_emu = 0
            return

        # -------------------------------------------------- XOR 0x40 ---- #
        if opcode == 0x40:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            dst = ((byte >> 4) - 1) & 3
            src = ((byte & 0xF) - 1) & 3

            v1 = self._get_reg(dst)
            v2 = self._get_reg(src)
            r = v1 ^ v2

            print(f"XOR 0x40 -> {self.to_reg(dst)}= {hex(v1)} ^ {hex(v2)}={hex(r)}")

            self._set_reg(dst, r)
            return

        # -------------------------------------------------- MUL 0x50 ---- #
        if opcode == 0x50:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            r1 = ((byte >> 4) - 1) & 3
            r2 = ((byte & 0xF) - 1) & 3
            prod = (self._get_reg(r1) * self._get_reg(r2)) & 0xFFFFFFFFFFFFFFFF
            ctx.A = prod & 0xFFFFFFFF
            ctx.D = (prod >> 32) & 0xFFFFFFFF
            print(f"MUL 0x50-> A={hex(ctx.A)}|D={hex(ctx.D)}")
            return

        # -------------------------------------------------- MUL IMM 0x51 -#
        if opcode == 0x51:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            imm  = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            r2   = (((byte >> 4) + 3) & 3)        # formule du binaire
            prod = (imm * self._get_reg(r2)) & 0xFFFFFFFFFFFFFFFF
            print(f"MUL 0x51-> {hex(imm)}*{hex(self._get_reg(r2))} = {hex(prod)}")
            ctx.A = prod & 0xFFFFFFFF
            ctx.D = (prod >> 32) & 0xFFFFFFFF
            print(f"MUL 0x51 A->{hex(ctx.A)} | D={hex(ctx.D)}")
            return

        # -------------------------------------------------- CALL 0x60 --- #
        if opcode == 0x60:
            target = ctx.get_memory_emu_dword(ctx.PC)
            ctx.PC += 4
            ctx.push_dword_to_stack(ctx.PC)       # adresse de retour
            ctx.PC = target & 0xFFFFFFFF
            ctx.dump_emu(print_stack=True)
            print(f"call {hex(ctx.PC)}")
            return

        # --------------------------------------------------- RET 0x61 --- #
        if opcode == 0x61:
            byte = ctx.read_mem(ctx.PC, 1)[0]
            ctx.PC += 1
            if ctx.patch_id == 0:
                ctx.SP = 0x00008EE2
                ctx.patch_id += 1
            else:
                ctx.SP = (ctx.SP + 4 * byte) & 0xFFFFFFFF
            ctx.PC = ctx.pop_dword_from_stack()
            print(f"ret {hex(ctx.PC)}")
            return

        # ------------------------------------- JZ / JNZ / JN / JMP ------ #
        if opcode in (0x62, 0x63, 0x64, 0x68):
            print(f"opcode JZ/JNZ/JN/JMP {opcode}")
            ctx.cpt += 1
            #ctx.dump_emu(print_stack=True)
            if ctx.cpt == 19:
                print(f"TAKE BRANCH2")
                target = ctx.get_memory_emu_dword(ctx.PC)
                ctx.PC = target & 0xFFFFFFFF
                return
            taken = False
            if opcode == 0x62:                    # JZ  (flag bit0 == 1)
                taken = (ctx.flag & 1) != 0
            elif opcode == 0x63:                  # JNZ (flag bit0 == 0)
                taken = (ctx.flag & 1) == 0
            elif opcode == 0x64:                  # JN  (flag bit1 == 1)
                taken = (ctx.flag & 2) != 0
            elif opcode == 0x68:                  # JMP inconditionnel
                taken = True

            if taken:
                target = ctx.get_memory_emu_dword(ctx.PC)
                ctx.PC = target & 0xFFFFFFFF
                print(f"TAKEN BRANCH | new pc = {hex(ctx.PC)}")
            else:
                print(f"NO TAKE BRANCH")
                ctx.PC += 4
            return

        # ------------------------------------------------------ TODO ---- #
        # Les opcodes >= 0xC0 gèrent plusieurs modes d’adressage mémoire.
        if opcode >= 0xC0:
            dst_code = (opcode >> 3) & 7
            src_code = opcode & 7
            src_mode_indirect = (opcode & 4) == 0      # bit 2 == 0
            ext_low2  = op_ext & 3                     # v10  → src déréf
            ext_high  = op_ext >> 2                    # v4>>2→ dst [Reg]

            # --------- 1)  Récupérer la valeur source  -------- #
            if src_mode_indirect:
                # src = Reg
                src_val = self._get_reg(src_code)
                if ext_low2:                           # [Reg]
                    src_val = ctx.get_memory_emu_dword(src_val)
            else:
                # src = variantes 4 / 5 / 6
                if   src_code == 4:                    # src = [imm32]
                    addr    = ctx.get_memory_emu_dword(ctx.PC); ctx.PC += 4
                    src_val = ctx.get_memory_emu_dword(addr)
                elif src_code == 5:                    # src = imm32
                    src_val = ctx.get_memory_emu_dword(ctx.PC); ctx.PC += 4
                elif src_code == 6:                    # src = SP / [SP]
                    src_val = ctx.SP
                    if ext_low2:
                        src_val = ctx.get_memory_emu_dword(src_val)
                else:
                    self.continue_emu = 0
                    return
                if ext_low2:                           # déréf interdit ici
                    self.continue_emu = 0
                    return

            # --------- 2)  Écrire le résultat dans la destination -------- #
            if ext_high:                               # dst = [RegDst]
                if dst_code >= 4:                      # RegDst doit être A-D
                    self.continue_emu = 0
                    return
                addr = self._get_reg(dst_code)
                ctx.write_to_mem_dword(addr, src_val)
                print(f"opcode EH {hex(addr)}={hex(src_val)}")
                return

            if (opcode & 0x20) == 0:                   # dst = RegDst
                self._set_reg(dst_code, src_val)
                print(f"_set_reg 0X20 {self.to_reg(dst_code)}={hex(src_val)}")
                return

            # dst = [imm32]  (seulement si dst==SP et src!=6)
            if dst_code != 4 or src_code == 6:
                ctx.exec_failed = 1
                self.continue_emu = 0
                return
            addr = ctx.get_memory_emu_dword(ctx.PC); ctx.PC += 4
            ctx.write_to_mem_dword(addr, src_val)
            print(f"opcode2 {hex(addr)}={hex(src_val)}")

            return

        # -------------------------------------------------- Unknown ----- #
        sys.stderr.write(f"[E] invalid RegVM instruction, pc=0x{ctx.PC - 1:08X} leader=0x{opcode:02X}\n")
        self.continue_emu = 0
        
    def _get_reg(self, idx: int) -> int:
        """Retourne A(0), B(1), C(2), D(3) ou SP(4)."""
        if idx == 0:
            return self.ctx.A
        if idx == 1:
            return self.ctx.B
        if idx == 2:
            return self.ctx.C
        if idx == 3:
            return self.ctx.D
        if idx == 4:
            return self.ctx.SP
        raise ValueError(f"Reg index out of range: {idx}")

    def _set_reg(self, idx: int, value: int) -> None:
        """Écrit A(0), B(1), C(2), D(3) ou SP(4). Valeur tronquée à 32 bits."""
        value &= 0xFFFFFFFF
        if idx == 0:
            self.ctx.A = value
        elif idx == 1:
            self.ctx.B = value
        elif idx == 2:
            self.ctx.C = value
        elif idx == 3:
            self.ctx.D = value
        elif idx == 4:
            self.ctx.SP = value
        else:
            raise ValueError(f"Reg index out of range: {idx}")

    def to_reg(self, idx):
        if idx == 0:
            return "A"
        elif idx == 1:
            return "B"
        elif idx == 2:
            return "C"
        elif idx == 3:
            return "D"
        elif idx == 4:
            return "SP"
        else:
            raise ValueError(f"Reg index out of range: {idx}")

    def run_step(self):
        arch = self.get_arch_mode()   
        print(f"Arch={arch}")     
        if (not arch):
            self.run_step_arch1()
        elif (arch == 1):
            self.run_step_arch2()
        else:
            self.continue_emu = 0

    def run(self):
        print("[+] Emulator is running...")
        while self.continue_emu:
            self.run_step()
        print("[+] Emu has ended")
        self.ctx.dump_emu(print_stack=1)

if __name__ == "__main__":
    emu = Emulator("./crackme.masm")
    emu.run()

#Q1: 2405061754
#Q2: 3 .   .AAAAAAAABBBBBBBBCCCCCCCC
#Q3: 45483068
```