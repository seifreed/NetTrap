// sample_gui.c - Default GUI exe fakefile for INetSim
//
// (c)2007-2019 Matthias Eckert, Thomas Hungenberg
//
// Compile: i686-w64-mingw32-gcc -o sample_gui.exe sample_gui.c

#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    MessageBox (NULL, "This is the INetSim default GUI binary" , "INetSim", 0);
    return 0;
}
