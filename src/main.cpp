#include <stdio.h>
#include <iostream>
#include <fstream>
#include "des.h"

using namespace std;
using namespace encryption;

int main (int argc, char **argv)
{
  
  std::string cipher;
  string line;
  ifstream myfile ("document.txt");
  if (myfile.is_open())
  {
    while ( getline (myfile,line) )
    {
      cipher+= line;
    }
    myfile.close();
  }

  DES des(std::bitset<9>("111000111"));
  std::vector<bitset<12>> e;
  e = des.Encrypt(cipher);
  
  fstream yourfile ("encrypted.txt");
  for (auto l : e)
  {
    yourfile << l;
  }
  yourfile.close();
  
  std::vector<bitset<12>> o;
  yourfile.open("encrypted.txt");
  if (yourfile.is_open())
  {
    while ( getline (yourfile,line) )
    {
      o.push_back(std::bitset<12>(line));
    }
    yourfile.close();
  }

  o = des.Decrypt(e);
  for (auto l : o)
  {
    cout << (char)(l.to_ulong() >> 4);
  }
  return 1;
}
