#include "des.h"

namespace encryption
{
  constexpr char s1[2][8] = 
  {
    {0x5, 0x2, 0x1, 0x6, 0x3, 0x4, 0x7, 0},
    {0x1, 0x4, 0x6, 0x2, 0x0, 0x7, 0x5, 0x3}
  };

  constexpr char s2[2][8] = 
  {
    {0x4, 0x0, 0x6, 0x5, 0x7, 0x1, 0x3, 0x2},
    {0x5, 0x3, 0x0, 0x7, 0x6, 0x2, 0x1, 0x4}
  };

  void DES::getKey()
  {
    for (int round = 0; round < 9; round++)
    {
      std::bitset<8> key;
      for (int i = 0; i < 8; i++)
      {
        int idx = 9 - 1 - round - i;
        idx = (idx >= 0)? idx : (idx + 9);
        key[7-i] = key_[idx];
      }
      key_round_.push_back(key);
    } 
  }

  std::bitset<8> DES::ExpandText(std::bitset<6> text)
  {
    std::bitset<8> exText;
    exText[0] = text[0]; exText[1] = text[1]; 
    exText[2] = text[3]; exText[3] = text[2];
    exText[4] = text[3]; exText[5] = text[2];
    exText[6] = text[4]; exText[7] = text[5];
    
    return exText;
  }

  std::bitset<6> DES::SBoxes(std::bitset<8> sBox)
  {
    std::bitset<6> sBox_output;
    sBox_output.reset();
    sBox_output = 
      std::bitset<6>(s2[sBox[3]][(char)sBox.to_ulong() & 0x7]);
    sBox_output = 
      std::bitset<6>((sBox_output.to_ulong()) | ((s1[sBox[7]][((char)sBox.to_ulong() & 0x70) >> 4]) << 3));
   return sBox_output;  
  }
  
  std::bitset<12> DES::EncryptUtil(std::bitset<12> text, int round)
  {
     if (round == 9)
        return text;
     std::bitset<6> left_i_1 = ((text.to_ulong() & 0xFC0) >> 6);
     std::bitset<6> right_i_1 = (text.to_ulong() & 0X3F);
     std::bitset<8> ex = ExpandText(right_i_1);
     ex ^= key_round_[round];
     std::bitset<6> right_i = SBoxes(ex);
     right_i ^= left_i_1;
     round = round + 1; 
     std::bitset<12> encrypt_text = 
        std::bitset<12>((right_i_1.to_ulong() << 6) | right_i.to_ulong());
      return (EncryptUtil(encrypt_text, round));
  }

  std::vector<std::bitset<12>>
  DES::Encrypt (std::string cipherText)
  {
    std::vector<std::bitset<12>> out;
    for (int i = 0; i < cipherText.length(); i++)
    {
      std::bitset<12> text(0);
      text = std::bitset<12> ((cipherText[i] << 4));
      std::bitset<12> val = EncryptUtil(text, 0);
      val = std::bitset<12>(((val.to_ulong() & 0x3F) << 6) | 
        ((val.to_ulong() & 0xFC0) >> 6));
      
      out.push_back(val);
    }
    return out;
  } 

   std::bitset<12> DES::DecryptUtil(std::bitset<12> text, int round)
  {
     if (round == -1)
        return text;
     std::bitset<6> right_i_1 = std::bitset<6>(text.to_ullong() & 0X3F);
     std::bitset<6> left_i_1 = 
        std::bitset<6>((text.to_ullong() & 0xFC0) >> 6);
     std::bitset<8> ex = ExpandText(right_i_1);
     ex ^= key_round_[round];
     std::bitset<6> right_i = SBoxes(ex);
     right_i ^= left_i_1;
     round = round - 1; 
     std::bitset<12> encrypt_text = 
        std::bitset<12>((right_i_1.to_ulong() << 6) | right_i.to_ulong());
      return (DecryptUtil(encrypt_text, round));
  }

  std::vector<std::bitset<12>>
  DES::Decrypt (std::vector<std::bitset<12>> text)
  {
    std::vector<std::bitset<12>> out;
    for (int i = 0; i < text.size(); i++)
    { 
       std::bitset<12> val = DecryptUtil(text[i], 8);
       val = std::bitset<12>(((val.to_ulong() & 0x3F) << 6) | 
        ((val.to_ulong() & 0xFC0) >> 6));
       out.push_back(val); 
    }  
    return out;
  }
}
