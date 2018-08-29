from de_ollvm import *

# nullcon 2016, rev300 pseudorandom
prog = '''
__int64 __fastcall sub_400B40(int a1)
{
  signed int v1; // eax@5
  signed int v3; // [sp+10h] [bp-Ch]@1
  unsigned int v4; // [sp+14h] [bp-8h]@1
  int v5; // [sp+18h] [bp-4h]@1

  v5 = a1;
  v4 = 0;
  v3 = 1523738799;
  while ( v3 != -1781392209 )
  {
    if ( v3 == -321715599 )
    {
      v5 = ~(~(v5 - 1) | ~v5);
      ++v4;
      v3 = 1523738799;
    }
    else if ( v3 == 1523738799 )
    {
      v1 = -1781392209;
      if ( v5 )
        v1 = -321715599;
      v3 = v1;
    }
  }
  return v4;
}

__int64 __fastcall sub_400C30(int a1)
{
  signed int v1; // eax@24
  signed int v2; // eax@29
  signed int v3; // eax@32
  signed int v5; // [sp+40h] [bp-18h]@1
  int v6; // [sp+44h] [bp-14h]@1
  signed int v7; // [sp+48h] [bp-10h]@1
  int v8; // [sp+50h] [bp-8h]@0

  v7 = 1;
  v6 = 0;
  v5 = 1686268861;
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( v5 <= -649527273 )
        {
          if ( v5 == -785991200 )
          {
            v8 = 0;
            v5 = 654278669;
          }
        }
        if ( v5 > 654278668 )
          break;
        if ( v5 == -649527272 )
        {
          v8 = v6;
          v5 = 654278669;
        }
      }
      if ( v5 <= 1010088293 )
        break;
      if ( v5 > 1759468863 )
      {
        if ( v5 == 1759468864 )
        {
          v3 = 1164544472;
          if ( a1 & (~v7 ^ a1) )
            v3 = 1060084854;
          v5 = v3;
        }
      }
      else if ( v5 > 1686268860 )
      {
        if ( v5 == 1686268861 )
        {
          v1 = -785991200;
          if ( a1 )
            v1 = 1010088294;
          v5 = v1;
        }
      }
      else if ( v5 > 1567797097 )
      {
        if ( v5 == 1567797098 )
        {
          v2 = -649527272;
          if ( v7 )
            v2 = 1759468864;
          v5 = v2;
        }
      }
      else
      {
        switch ( v5 )
        {
          case 1010088294:
            v5 = 1567797098;
            break;
          case 1060084854:
            v6 = ~(~v7 | ~a1);
            v5 = 1164544472;
            break;
          case 1164544472:
            v7 *= 2;
            v5 = 1567797098;
            break;
        }
      }
    }
  }
  while ( v5 != 654278669 );
  return (unsigned int)v8;
}
__int64 __fastcall sub_400EA0(__int64 a1, int a2)
{
  signed int v2; // eax@12
  signed int v3; // eax@15
  int v4; // ST00_4@18
  int v5; // eax@18
  signed int v7; // [sp+28h] [bp-18h]@1
  unsigned int v8; // [sp+38h] [bp-8h]@0

  v7 = -1460804643;
  do
  {
    while ( 1 )
    {
      while ( v7 <= -857087489 )
      {
        if ( v7 == -1460804643 )
        {
          v2 = 218564280;
          if ( a2 )
            v2 = 527506268;
          v7 = v2;
        }
      }
      if ( v7 <= 218564279 )
        break;
      if ( v7 == 218564280 )
        fail();
      if ( v7 == 484338753 )
      {
        v4 = a1 & (find_highest_bit(a1) ^ a1);
        v5 = find_highest_bit(a1);
        v8 = (2 * v5 ^ v4 | 2 * v5 & v4) == a2 + (_DWORD)a1;
        v7 = -857087488;
      }
      else if ( v7 == 527506268 )
      {
        v3 = 218564280;
        if ( (_DWORD)a1 )
          v3 = 484338753;
        v7 = v3;
      }
    }
  }
  while ( v7 != -857087488 );
  return v8;
}
'''.strip()

f1, f2, f3 = parse_ida_c(prog.split('\n'))[0]
f1.pprint(check=True)
f2.pprint(check=True)
f3.pprint(check=True)

print '-' * 100

unflatten_func_source(f1, 'v3').pprint()
unflatten_func_source(f2, 'v5').pprint()
unflatten_func_source(f3, 'v7').pprint()
