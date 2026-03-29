// sample_con.c - Default console exe fakefile for INetSim
//
// (c)2007-2019 Matthias Eckert, Thomas Hungenberg
//
// Compile: i686-w64-mingw32-gcc -o sample_con.exe sample_con.c

#include <stdio.h>
#include <windows.h>

void main()
{
    printf("This is the INetSim default console binary\n");
    Sleep(10000);
}
