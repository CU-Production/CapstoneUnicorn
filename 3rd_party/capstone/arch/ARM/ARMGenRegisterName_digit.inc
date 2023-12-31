/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

/// getRegisterName - This method is automatically generated by tblgen
/// from the register set description.  This returns the assembler name
/// for the specified register.
static const char *getRegisterName_digit(unsigned RegNo)
{

#ifndef CAPSTONE_DIET
  static const char AsmStrs[] = {
  /* 0 */ 'D', '4', '_', 'D', '6', '_', 'D', '8', '_', 'D', '1', '0', 0,
  /* 13 */ 'D', '7', '_', 'D', '8', '_', 'D', '9', '_', 'D', '1', '0', 0,
  /* 26 */ 'Q', '7', '_', 'Q', '8', '_', 'Q', '9', '_', 'Q', '1', '0', 0,
  /* 39 */ 'd', '1', '0', 0,
  /* 43 */ 'q', '1', '0', 0,
  /* 47 */ 'r', '1', '0', 0,
  /* 51 */ 's', '1', '0', 0,
  /* 55 */ 'D', '1', '4', '_', 'D', '1', '6', '_', 'D', '1', '8', '_', 'D', '2', '0', 0,
  /* 71 */ 'D', '1', '7', '_', 'D', '1', '8', '_', 'D', '1', '9', '_', 'D', '2', '0', 0,
  /* 87 */ 'd', '2', '0', 0,
  /* 91 */ 's', '2', '0', 0,
  /* 95 */ 'D', '2', '4', '_', 'D', '2', '6', '_', 'D', '2', '8', '_', 'D', '3', '0', 0,
  /* 111 */ 'D', '2', '7', '_', 'D', '2', '8', '_', 'D', '2', '9', '_', 'D', '3', '0', 0,
  /* 127 */ 'd', '3', '0', 0,
  /* 131 */ 's', '3', '0', 0,
  /* 135 */ 'd', '0', 0,
  /* 138 */ 'q', '0', 0,
  /* 141 */ 'm', 'v', 'f', 'r', '0', 0,
  /* 147 */ 's', '0', 0,
  /* 150 */ 'D', '9', '_', 'D', '1', '0', '_', 'D', '1', '1', 0,
  /* 161 */ 'D', '5', '_', 'D', '7', '_', 'D', '9', '_', 'D', '1', '1', 0,
  /* 174 */ 'Q', '8', '_', 'Q', '9', '_', 'Q', '1', '0', '_', 'Q', '1', '1', 0,
  /* 188 */ 'R', '1', '0', '_', 'R', '1', '1', 0,
  /* 196 */ 'd', '1', '1', 0,
  /* 200 */ 'q', '1', '1', 0,
  /* 204 */ 'r', '1', '1', 0,
  /* 208 */ 's', '1', '1', 0,
  /* 212 */ 'D', '1', '9', '_', 'D', '2', '0', '_', 'D', '2', '1', 0,
  /* 224 */ 'D', '1', '5', '_', 'D', '1', '7', '_', 'D', '1', '9', '_', 'D', '2', '1', 0,
  /* 240 */ 'd', '2', '1', 0,
  /* 244 */ 's', '2', '1', 0,
  /* 248 */ 'D', '2', '9', '_', 'D', '3', '0', '_', 'D', '3', '1', 0,
  /* 260 */ 'D', '2', '5', '_', 'D', '2', '7', '_', 'D', '2', '9', '_', 'D', '3', '1', 0,
  /* 276 */ 'd', '3', '1', 0,
  /* 280 */ 's', '3', '1', 0,
  /* 284 */ 'Q', '0', '_', 'Q', '1', 0,
  /* 290 */ 'R', '0', '_', 'R', '1', 0,
  /* 296 */ 'd', '1', 0,
  /* 299 */ 'q', '1', 0,
  /* 302 */ 'm', 'v', 'f', 'r', '1', 0,
  /* 308 */ 's', '1', 0,
  /* 311 */ 'D', '6', '_', 'D', '8', '_', 'D', '1', '0', '_', 'D', '1', '2', 0,
  /* 325 */ 'D', '9', '_', 'D', '1', '0', '_', 'D', '1', '1', '_', 'D', '1', '2', 0,
  /* 340 */ 'Q', '9', '_', 'Q', '1', '0', '_', 'Q', '1', '1', '_', 'Q', '1', '2', 0,
  /* 355 */ 'd', '1', '2', 0,
  /* 359 */ 'q', '1', '2', 0,
  /* 363 */ 'r', '1', '2', 0,
  /* 367 */ 's', '1', '2', 0,
  /* 371 */ 'D', '1', '6', '_', 'D', '1', '8', '_', 'D', '2', '0', '_', 'D', '2', '2', 0,
  /* 387 */ 'D', '1', '9', '_', 'D', '2', '0', '_', 'D', '2', '1', '_', 'D', '2', '2', 0,
  /* 403 */ 'd', '2', '2', 0,
  /* 407 */ 's', '2', '2', 0,
  /* 411 */ 'D', '0', '_', 'D', '2', 0,
  /* 417 */ 'D', '0', '_', 'D', '1', '_', 'D', '2', 0,
  /* 426 */ 'Q', '1', '_', 'Q', '2', 0,
  /* 432 */ 'd', '2', 0,
  /* 435 */ 'q', '2', 0,
  /* 438 */ 'm', 'v', 'f', 'r', '2', 0,
  /* 444 */ 's', '2', 0,
  /* 447 */ 'f', 'p', 'i', 'n', 's', 't', '2', 0,
  /* 455 */ 'D', '7', '_', 'D', '9', '_', 'D', '1', '1', '_', 'D', '1', '3', 0,
  /* 469 */ 'D', '1', '1', '_', 'D', '1', '2', '_', 'D', '1', '3', 0,
  /* 481 */ 'Q', '1', '0', '_', 'Q', '1', '1', '_', 'Q', '1', '2', '_', 'Q', '1', '3', 0,
  /* 497 */ 'd', '1', '3', 0,
  /* 501 */ 'q', '1', '3', 0,
  /* 505 */ 's', 'p', 0, 0,
  /* 509 */ 's', '1', '3', 0,
  /* 513 */ 'D', '1', '7', '_', 'D', '1', '9', '_', 'D', '2', '1', '_', 'D', '2', '3', 0,
  /* 529 */ 'D', '2', '1', '_', 'D', '2', '2', '_', 'D', '2', '3', 0,
  /* 541 */ 'd', '2', '3', 0,
  /* 545 */ 's', '2', '3', 0,
  /* 549 */ 'D', '1', '_', 'D', '3', 0,
  /* 555 */ 'D', '1', '_', 'D', '2', '_', 'D', '3', 0,
  /* 564 */ 'Q', '0', '_', 'Q', '1', '_', 'Q', '2', '_', 'Q', '3', 0,
  /* 576 */ 'R', '2', '_', 'R', '3', 0,
  /* 582 */ 'd', '3', 0,
  /* 585 */ 'q', '3', 0,
  /* 588 */ 'r', '3', 0,
  /* 591 */ 's', '3', 0,
  /* 594 */ 'D', '8', '_', 'D', '1', '0', '_', 'D', '1', '2', '_', 'D', '1', '4', 0,
  /* 609 */ 'D', '1', '1', '_', 'D', '1', '2', '_', 'D', '1', '3', '_', 'D', '1', '4', 0,
  /* 625 */ 'Q', '1', '1', '_', 'Q', '1', '2', '_', 'Q', '1', '3', '_', 'Q', '1', '4', 0,
  /* 641 */ 'd', '1', '4', 0,
  /* 645 */ 'q', '1', '4', 0,
  /* 649 */ 'l', 'r', 0, 0,
  /* 653 */ 's', '1', '4', 0,
  /* 657 */ 'D', '1', '8', '_', 'D', '2', '0', '_', 'D', '2', '2', '_', 'D', '2', '4', 0,
  /* 673 */ 'D', '2', '1', '_', 'D', '2', '2', '_', 'D', '2', '3', '_', 'D', '2', '4', 0,
  /* 689 */ 'd', '2', '4', 0,
  /* 693 */ 's', '2', '4', 0,
  /* 697 */ 'D', '0', '_', 'D', '2', '_', 'D', '4', 0,
  /* 706 */ 'D', '1', '_', 'D', '2', '_', 'D', '3', '_', 'D', '4', 0,
  /* 718 */ 'Q', '1', '_', 'Q', '2', '_', 'Q', '3', '_', 'Q', '4', 0,
  /* 730 */ 'd', '4', 0,
  /* 733 */ 'q', '4', 0,
  /* 736 */ 'r', '4', 0,
  /* 739 */ 's', '4', 0,
  /* 742 */ 'D', '9', '_', 'D', '1', '1', '_', 'D', '1', '3', '_', 'D', '1', '5', 0,
  /* 757 */ 'D', '1', '3', '_', 'D', '1', '4', '_', 'D', '1', '5', 0,
  /* 769 */ 'Q', '1', '2', '_', 'Q', '1', '3', '_', 'Q', '1', '4', '_', 'Q', '1', '5', 0,
  /* 785 */ 'd', '1', '5', 0,
  /* 789 */ 'q', '1', '5', 0,
  /* 793 */ 's', '1', '5', 0,
  /* 797 */ 'D', '1', '9', '_', 'D', '2', '1', '_', 'D', '2', '3', '_', 'D', '2', '5', 0,
  /* 813 */ 'D', '2', '3', '_', 'D', '2', '4', '_', 'D', '2', '5', 0,
  /* 825 */ 'd', '2', '5', 0,
  /* 829 */ 's', '2', '5', 0,
  /* 833 */ 'D', '1', '_', 'D', '3', '_', 'D', '5', 0,
  /* 842 */ 'D', '3', '_', 'D', '4', '_', 'D', '5', 0,
  /* 851 */ 'Q', '2', '_', 'Q', '3', '_', 'Q', '4', '_', 'Q', '5', 0,
  /* 863 */ 'R', '4', '_', 'R', '5', 0,
  /* 869 */ 'd', '5', 0,
  /* 872 */ 'q', '5', 0,
  /* 875 */ 'r', '5', 0,
  /* 878 */ 's', '5', 0,
  /* 881 */ 'D', '1', '0', '_', 'D', '1', '2', '_', 'D', '1', '4', '_', 'D', '1', '6', 0,
  /* 897 */ 'D', '1', '3', '_', 'D', '1', '4', '_', 'D', '1', '5', '_', 'D', '1', '6', 0,
  /* 913 */ 'd', '1', '6', 0,
  /* 917 */ 's', '1', '6', 0,
  /* 921 */ 'D', '2', '0', '_', 'D', '2', '2', '_', 'D', '2', '4', '_', 'D', '2', '6', 0,
  /* 937 */ 'D', '2', '3', '_', 'D', '2', '4', '_', 'D', '2', '5', '_', 'D', '2', '6', 0,
  /* 953 */ 'd', '2', '6', 0,
  /* 957 */ 's', '2', '6', 0,
  /* 961 */ 'D', '0', '_', 'D', '2', '_', 'D', '4', '_', 'D', '6', 0,
  /* 973 */ 'D', '3', '_', 'D', '4', '_', 'D', '5', '_', 'D', '6', 0,
  /* 985 */ 'Q', '3', '_', 'Q', '4', '_', 'Q', '5', '_', 'Q', '6', 0,
  /* 997 */ 'd', '6', 0,
  /* 1000 */ 'q', '6', 0,
  /* 1003 */ 'r', '6', 0,
  /* 1006 */ 's', '6', 0,
  /* 1009 */ 'D', '1', '1', '_', 'D', '1', '3', '_', 'D', '1', '5', '_', 'D', '1', '7', 0,
  /* 1025 */ 'D', '1', '5', '_', 'D', '1', '6', '_', 'D', '1', '7', 0,
  /* 1037 */ 'd', '1', '7', 0,
  /* 1041 */ 's', '1', '7', 0,
  /* 1045 */ 'D', '2', '1', '_', 'D', '2', '3', '_', 'D', '2', '5', '_', 'D', '2', '7', 0,
  /* 1061 */ 'D', '2', '5', '_', 'D', '2', '6', '_', 'D', '2', '7', 0,
  /* 1073 */ 'd', '2', '7', 0,
  /* 1077 */ 's', '2', '7', 0,
  /* 1081 */ 'D', '1', '_', 'D', '3', '_', 'D', '5', '_', 'D', '7', 0,
  /* 1093 */ 'D', '5', '_', 'D', '6', '_', 'D', '7', 0,
  /* 1102 */ 'Q', '4', '_', 'Q', '5', '_', 'Q', '6', '_', 'Q', '7', 0,
  /* 1114 */ 'R', '6', '_', 'R', '7', 0,
  /* 1120 */ 'd', '7', 0,
  /* 1123 */ 'q', '7', 0,
  /* 1126 */ 'r', '7', 0,
  /* 1129 */ 's', '7', 0,
  /* 1132 */ 'D', '1', '2', '_', 'D', '1', '4', '_', 'D', '1', '6', '_', 'D', '1', '8', 0,
  /* 1148 */ 'D', '1', '5', '_', 'D', '1', '6', '_', 'D', '1', '7', '_', 'D', '1', '8', 0,
  /* 1164 */ 'd', '1', '8', 0,
  /* 1168 */ 's', '1', '8', 0,
  /* 1172 */ 'D', '2', '2', '_', 'D', '2', '4', '_', 'D', '2', '6', '_', 'D', '2', '8', 0,
  /* 1188 */ 'D', '2', '5', '_', 'D', '2', '6', '_', 'D', '2', '7', '_', 'D', '2', '8', 0,
  /* 1204 */ 'd', '2', '8', 0,
  /* 1208 */ 's', '2', '8', 0,
  /* 1212 */ 'D', '2', '_', 'D', '4', '_', 'D', '6', '_', 'D', '8', 0,
  /* 1224 */ 'D', '5', '_', 'D', '6', '_', 'D', '7', '_', 'D', '8', 0,
  /* 1236 */ 'Q', '5', '_', 'Q', '6', '_', 'Q', '7', '_', 'Q', '8', 0,
  /* 1248 */ 'd', '8', 0,
  /* 1251 */ 'q', '8', 0,
  /* 1254 */ 'r', '8', 0,
  /* 1257 */ 's', '8', 0,
  /* 1260 */ 'D', '1', '3', '_', 'D', '1', '5', '_', 'D', '1', '7', '_', 'D', '1', '9', 0,
  /* 1276 */ 'D', '1', '7', '_', 'D', '1', '8', '_', 'D', '1', '9', 0,
  /* 1288 */ 'd', '1', '9', 0,
  /* 1292 */ 's', '1', '9', 0,
  /* 1296 */ 'D', '2', '3', '_', 'D', '2', '5', '_', 'D', '2', '7', '_', 'D', '2', '9', 0,
  /* 1312 */ 'D', '2', '7', '_', 'D', '2', '8', '_', 'D', '2', '9', 0,
  /* 1324 */ 'd', '2', '9', 0,
  /* 1328 */ 's', '2', '9', 0,
  /* 1332 */ 'D', '3', '_', 'D', '5', '_', 'D', '7', '_', 'D', '9', 0,
  /* 1344 */ 'D', '7', '_', 'D', '8', '_', 'D', '9', 0,
  /* 1353 */ 'Q', '6', '_', 'Q', '7', '_', 'Q', '8', '_', 'Q', '9', 0,
  /* 1365 */ 'R', '8', '_', 'R', '9', 0,
  /* 1371 */ 'd', '9', 0,
  /* 1374 */ 'q', '9', 0,
  /* 1377 */ 'r', '9', 0,
  /* 1380 */ 's', '9', 0,
  /* 1383 */ 'R', '1', '2', '_', 'S', 'P', 0,
  /* 1390 */ 'p', 'c', 0,
  /* 1393 */ 'f', 'p', 'e', 'x', 'c', 0,
  /* 1399 */ 'f', 'p', 's', 'i', 'd', 0,
  /* 1405 */ 'i', 't', 's', 't', 'a', 't', 'e', 0,
  /* 1413 */ 'f', 'p', 's', 'c', 'r', 0,
  /* 1419 */ 'a', 'p', 's', 'r', 0,
  /* 1424 */ 'c', 'p', 's', 'r', 0,
  /* 1429 */ 's', 'p', 's', 'r', 0,
  /* 1434 */ 'f', 'p', 'i', 'n', 's', 't', 0,
  /* 1441 */ 'f', 'p', 's', 'c', 'r', '_', 'n', 'z', 'c', 'v', 0,
  /* 1452 */ 'a', 'p', 's', 'r', '_', 'n', 'z', 'c', 'v', 0,
  };

  static const uint16_t RegAsmOffset[] = {
    1419, 1452, 1424, 1393, 1434, 1413, 1441, 1399, 1405, 649, 1390, 505, 1429, 135,
    296, 432, 582, 730, 869, 997, 1120, 1248, 1371, 39, 196, 355, 497, 641,
    785, 913, 1037, 1164, 1288, 87, 240, 403, 541, 689, 825, 953, 1073, 1204,
    1324, 127, 276, 447, 141, 302, 438, 138, 299, 435, 585, 733, 872, 1000,
    1123, 1251, 1374, 43, 200, 359, 501, 645, 789, 144, 305, 441, 588, 736,
    875, 1003, 1126, 1254, 1377, 47, 204, 363, 147, 308, 444, 591, 739, 878,
    1006, 1129, 1257, 1380, 51, 208, 367, 509, 653, 793, 917, 1041, 1168, 1292,
    91, 244, 407, 545, 693, 829, 957, 1077, 1208, 1328, 131, 280, 411, 549,
    700, 836, 967, 1087, 1218, 1338, 6, 167, 317, 461, 601, 749, 889, 1017,
    1140, 1268, 63, 232, 379, 521, 665, 805, 929, 1053, 1180, 1304, 103, 268,
    284, 426, 570, 724, 857, 991, 1108, 1242, 1359, 32, 180, 347, 489, 633,
    777, 564, 718, 851, 985, 1102, 1236, 1353, 26, 174, 340, 481, 625, 769,
    1383, 290, 576, 863, 1114, 1365, 188, 417, 555, 709, 842, 976, 1093, 1227,
    1344, 16, 150, 328, 469, 613, 757, 901, 1025, 1152, 1276, 75, 212, 391,
    529, 677, 813, 941, 1061, 1192, 1312, 115, 248, 697, 833, 964, 1084, 1215,
    1335, 3, 164, 314, 458, 597, 745, 885, 1013, 1136, 1264, 59, 228, 375,
    517, 661, 801, 925, 1049, 1176, 1300, 99, 264, 961, 1081, 1212, 1332, 0,
    161, 311, 455, 594, 742, 881, 1009, 1132, 1260, 55, 224, 371, 513, 657,
    797, 921, 1045, 1172, 1296, 95, 260, 420, 712, 979, 1230, 19, 332, 617,
    905, 1156, 79, 395, 681, 945, 1196, 119, 706, 973, 1224, 13, 325, 609,
    897, 1148, 71, 387, 673, 937, 1188, 111,
  };

  return AsmStrs+RegAsmOffset[RegNo-1];
#else
  return NULL;
#endif
}
