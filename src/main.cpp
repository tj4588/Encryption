#include <stdio.h>
#include <iostream>
#include "des.h"

using namespace std;
using namespace encryption;

int main (int argc, char **argv)
{
  std::string cipher("hello world");
  DES des(std::bitset<9>(0x0));
  std::string e;
  e = des.Encrypt(cipher);
  des.Decrypt(e);
  return 1;
}
