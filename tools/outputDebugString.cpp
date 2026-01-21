#include <windows.h>

int main()
{
    OutputDebugStringA("Hello world!");
    OutputDebugStringW(L"Hello world Unicode!漢");
}