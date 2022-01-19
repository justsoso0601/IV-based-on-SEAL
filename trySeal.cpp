
#include "seal/seal.h"
#include "trySeal.h"
#include <vector>
#include <chrono>
#include <cmath>
using namespace std;
using namespace seal;

vector<float> read(string file)
{
  string s;
  ifstream inf;
  inf.open(file); //打开F为文件所在位置，
  vector<float> readArray(0);
  float value = 0;

  while (getline(inf, s)) //getline(inf,s)是逐行读取inf中的文件信息
  {
    //cout << "read string is  " << s << endl;
    if (s != " " && s != "\n")
    {
      value = atof(s.c_str());
      readArray.push_back(value);
    }
  }

  std::cout << "read total: " << readArray.size() << endl;
  inf.close();
  return readArray;
}

int main()
{

  //////////////////////CKKS TEST/////////////////////////////////////////

  //开始计时
  auto start = std::chrono::steady_clock::now();

  cout << "-------------------------------------------------------------" << endl;
  cout << "Second show the process of IV computation" << endl;

  //首先构建参数容器 parms
  EncryptionParameters params2(scheme_type::ckks);
  /*CKKS有三个重要参数：
		1.poly_module_degree(模多项式的次数)
		2.coeff_modulus（密文多项式系数的模数）
		3.scale（浮点数值的放大规模）
		注意：CKKS里面没有明文多项式的系数模数，因为CKKS里面把噪声也视为明文的一部分，不需要模数来去除噪声
  */

  size_t poly_modulus_degree2 = 16384; //slot数量为16384/2=8192
  params2.set_poly_modulus_degree(poly_modulus_degree2);
  params2.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree2, {60, 50, 50, 50, 50, 50, 50, 60})); //包括常数系数乘积在内，乘法深度为5

  //选用2^40进行编码，这个参数是精度的设置，噪声在10-15比特，所以最终计算的精度为25-30比特（40-15， 40-10）
  double scale = pow(2.0, 50);

  SEALContext context2(params2);

  //构建各模块
  //首先构建keygenerator，生成公钥、私钥和重线性化密钥50,
  KeyGenerator keygen2(context2);
  SecretKey secret_key2 = keygen2.secret_key();
  PublicKey public_key2;
  keygen2.create_public_key(public_key2);
  RelinKeys relin_keys2;
  keygen2.create_relin_keys(relin_keys2);
  GaloisKeys galois_keys2;
  keygen2.create_galois_keys(galois_keys2);

  //构建编码器，加密模块、运算器和解密模块
  //注意加密需要公钥pk；解密需要私钥sk；编码器需要scale
  Encryptor encryptor2(context2, public_key2);
  Evaluator evaluator2(context2);
  Decryptor decryptor2(context2, secret_key2);
  CKKSEncoder encoder2(context2);

  //泰勒展开式的10个系数不变量
  vector<double> coeff = {0.4342944819, -0.2171472409, 0.1447648273, -0.1085736204, 0.0868588963,
                          -0.0723824136, 0.0620420688, -0.0542868102, 0.0482549424, -0.0434294481};

  //编码这10个泰勒展开式系数常量
  const int coeffNum = 10;
  Plaintext COEEF[coeffNum];
  for (int i = 0; i < coeffNum; i++)
  {
    encoder2.encode(coeff[i], scale, COEEF[i]);
  }

  //针对每个特征进行IV值的计算，这里面主要用到每个分箱中的正样本和负样本数量，总的正样本和负样本数量
  //A对标签进行加密，B进行IV值计算
  //B根据实际数据和特征进行分箱，分箱时需注意每个分箱中数据不能为0，否则对数计算为无穷大，失去意义
  //注意分箱数、分箱正负样本数，总的正负样本数等参数与每个特征有关，不同的特征对应的这些数可以是不同的

  /*
  int TsampleNum = 400000;                   //样本总数,以40万为例, 样本总数=所有的正样本数+所有的负样本数
  const int feaNum = 2;                      //总的特征数量
  const int boxNum[feaNum] = {10, 10};       //分箱数, 10, 20, 30 ,40等, 不同的特征对应的分箱数可以不同
  double TposNum[feaNum] = {220000, 180000}; //所有的正样本数
  double TnegNum[feaNum] = {180000, 220000}; //所有的负样本数

  //10个分箱中每个分箱样本数量=10个分箱每个分箱的正样本+负样本数
  vector<double> SsampleNum[feaNum] = {{45000, 35000, 55000, 25000, 35000, 45000, 15000, 65000, 60000, 20000},
                                       {40000, 40000, 50000, 30000, 30000, 50000, 20000, 60000, 70000, 10000}};
  //10个分箱的正样本和负样本数
  //这里使用浮点而不用整型，符合编码的函数参数类型double
  vector<double> SposNum[feaNum] = {
      {25000, 15000, 40000, 20000, 15000, 15000, 10000, 45000, 30000, 5000},
      {20000, 15000, 40000, 15000, 15000, 15000, 10000, 15000, 30000, 5000},
  };

  vector<double> SnegNum[feaNum] = {
      {20000, 20000, 15000, 5000, 20000, 30000, 5000, 20000, 30000, 15000},
      {20000, 25000, 10000, 15000, 15000, 35000, 10000, 45000, 40000, 5000},
  };
*/

  int TsampleNum = 100;                    //样本总数, 样本总数=所有的正样本数+所有的负样本数
  const int feaNum = 5;                    //总的特征数量
  const int boxNum[feaNum] = {10, 10, 10, 10, 10}; //分箱数, 10, 20, 30 ,40等, 不同的特征对应的分箱数可以不同
  double TposNum[feaNum] = {60, 60, 60, 60, 60};   //所有的正样本数
  double TnegNum[feaNum] = {40, 40, 40, 40, 40};   //所有的负样本数

  //10个分箱中每个分箱样本数量=10个分箱每个分箱的正样本+负样本数
  vector<double> SsampleNum[feaNum] = {
      {8, 12, 7, 9, 8, 16, 10, 15, 9, 6},
      {8, 12, 7, 9, 8, 16, 10, 15, 9, 6},
      {8, 12, 7, 9, 8, 16, 10, 15, 9, 6},
      {8, 12, 7, 9, 8, 16, 10, 15, 9, 6},
      {8, 12, 7, 9, 8, 16, 10, 15, 9, 6}
  };
  //10个分箱的正样本和负样本数
  //这里使用浮点而不用整型，符合编码的函数参数类型double
  vector<double> SposNum[feaNum] = {
      {5, 7, 3, 4, 5, 10, 8, 9, 4, 5},
      {5, 7, 3, 4, 5, 10, 8, 9, 4, 5},
      {5, 7, 3, 4, 5, 10, 8, 9, 4, 5},
      {5, 7, 3, 4, 5, 10, 8, 9, 4, 5},
      {5, 7, 3, 4, 5, 10, 8, 9, 4, 5},
      };

  vector<double> SnegNum[feaNum] = {
      {3, 5, 4, 5, 3, 6, 2, 6, 5, 1},
      {3, 5, 4, 5, 3, 6, 2, 6, 5, 1},
      {3, 5, 4, 5, 3, 6, 2, 6, 5, 1},
      {3, 5, 4, 5, 3, 6, 2, 6, 5, 1},
      {3, 5, 4, 5, 3, 6, 2, 6, 5, 1}
      };



  int TboxNum = 0; //分箱总数
  for (int i = 0; i < feaNum; i++)
  {
    TboxNum += boxNum[i];
  }

  //A对每个特征所有的样本的标签进行加密，并发送给B
  //先按上面的数据造出对应的明文标签（满足上面的正样本和负样本数）
  vector<double> alltag[feaNum] = {};
  for (int i = 0; i < feaNum; i++)
  {
    for (int j = 0; j < boxNum[i]; j++) //注意SposNum[i]的size大小就是分箱数量
    {
      for (int k = 0; k < SposNum[i][j]; k++)
      {
        alltag[i].push_back(1.0); //正样本
      }

      for (int k = 0; k < SnegNum[i][j]; k++)
      {
        alltag[i].push_back(0.0); //负样本
      }
    }
  }

  //A对每个特征的alltag进行加密，然后发送给B
  map<int, Ciphertext> cipherTagMap[feaNum];

  for (int i = 0; i < feaNum; i++)
  {
    //生成每个样本标签的密文
    for (int j = 0; j < TsampleNum; j++) //每个特征的总样本数都是相同的
    {
      vector<double> sampleTag = {};
      sampleTag.push_back(alltag[i][j]); //形成标签的vector，这样才方便后续计算时一个分箱的tag求和

      Plaintext PsampleTag;
      encoder2.encode(sampleTag, scale, PsampleTag);
      Ciphertext CsampleTag;
      encryptor2.encrypt(PsampleTag, CsampleTag);

      //插入map
      pair<map<int, Ciphertext>::iterator, bool> ret;
      ret = cipherTagMap[i].insert(pair<int, Ciphertext>(j, CsampleTag));
      if (ret.second == false)
      {
        cout << "The feaNum " << i << "of element " << j << "already existed!" << endl;
      }
    }
  }

  //将cipherTagMap[feaNum]发送给B
  //B按照分箱里的样本编号对标签的密文进行求和
  //该demo里每个分箱的样本编号按全部样本的顺序排列，实际中每个分箱里的样本编号是随意的，但这不影响计算的逻辑
  //只需要把每个分箱对应的样本编号的密文取出即可（这就是我们用map的原因）

  //首先对每个特征下每个分箱的总数进行加密，用于后续减去正样本数得到负样本数
  Ciphertext CfeaPosNum[feaNum], CfeaNegNum[feaNum]; //每个特征的所有分箱的正样本和负样本数的密文向量

  for (int i = 0; i < feaNum; i++)
  {
    const int bNum = boxNum[i];
    Ciphertext CboxTotalNum[bNum];

    for (int j = 0; j < bNum; j++)
    {
      vector<double> vecBoxTotalNum = {};
      vecBoxTotalNum.push_back(SsampleNum[i][j]);
      Plaintext PboxTotalNum;
      encoder2.encode(vecBoxTotalNum, scale, PboxTotalNum);
      encryptor2.encrypt(PboxTotalNum, CboxTotalNum[j]);
    }

    cout << "here ok 1" << endl;
    //下面计算每个分箱的正样本和负样本数
    Ciphertext CboxPosSum[bNum]; //每个分箱正样本数
    Ciphertext CboxNegSum[bNum]; //每个分箱负样本数

    //如果这里分箱内的样本编号是随意的，则应先把样本编号数据抽取出来，再根据这些编号数据进行对应的密文求和

    //把0进行加密，方便求和
    vector<double> zero = {};
    zero.push_back(0.0);
    Plaintext Pzero;
    Ciphertext Czero;
    encoder2.encode(zero, scale, Pzero);
    encryptor2.encrypt(Pzero, Czero);

    int mapIndex = 0;
    for (int j = 0; j < bNum; j++)
    {
      if (j == 0)
      {
        mapIndex += 0;
      }
      else
      {
        mapIndex += SsampleNum[i][j - 1];
      }

      vector<double> zero = {};
      zero.push_back(0.0);
      Plaintext Pzero;
      Ciphertext Czero;
      encoder2.encode(zero, scale, Pzero);
      encryptor2.encrypt(Pzero, CboxPosSum[j]); //初始化为0的密文

      cout << "here ok 2_0" << endl;
      for (int k = mapIndex; k < mapIndex + SsampleNum[i][j]; k++)
      {
        evaluator2.add_inplace(CboxPosSum[j], cipherTagMap[i].at(k));
      }

      cout << "here ok 2_1" << endl;
      //用分箱总数的密文-分箱正样本数的密文：得到分箱负样本数的密文
      evaluator2.sub(CboxTotalNum[j], CboxPosSum[j], CboxNegSum[j]);
    }

    //把向量化的密文相加得到所有分箱的正负样本数的密文向量
    //Ciphertext CposNum, CnegNum;
    vector<double> zero1 = {};
    zero1.push_back(0.0);
    Plaintext Pzero1;
    encoder2.encode(zero1, scale, Pzero1);
    encryptor2.encrypt(Pzero1, CfeaPosNum[i]); //初始化为0的密文
    encryptor2.encrypt(Pzero1, CfeaNegNum[i]);

    for (int m = 0; m < bNum; m++)
    {
      //把对应的向量密文移位,然后加起来
      int shift = 0 - m; //负数往右移
      evaluator2.rotate_vector_inplace(CboxPosSum[m], shift, galois_keys2);
      evaluator2.rotate_vector_inplace(CboxNegSum[m], shift, galois_keys2);
      evaluator2.add_inplace(CfeaPosNum[i], CboxPosSum[m]);
      evaluator2.add_inplace(CfeaNegNum[i], CboxNegSum[m]);
    }
  }

  //现在把不同特征的正样本数密文向量和负样本数密文向量形成一个向量
  Ciphertext CposNum, CnegNum;

  vector<double> zero2 = {};
  zero2.push_back(0.0);
  Plaintext Pzero2;
  encoder2.encode(zero2, scale, Pzero2);
  encryptor2.encrypt(Pzero2, CposNum); //初始化为0的密文
  encryptor2.encrypt(Pzero2, CnegNum);

  int feaShiftSum = 0;
  for (int i = 0; i < feaNum; i++)
  {
    //把对应的向量密文移位,然后加起来   
    if (i == 0)
    {
      feaShiftSum += 0;
    }
    else
    {
      feaShiftSum += boxNum[i - 1];
    }

    int shift = 0 - feaShiftSum; //负数往右移
    evaluator2.rotate_vector_inplace(CfeaPosNum[i], shift, galois_keys2);
    evaluator2.rotate_vector_inplace(CfeaNegNum[i], shift, galois_keys2);
    evaluator2.add_inplace(CposNum, CfeaPosNum[i]);
    evaluator2.add_inplace(CnegNum, CfeaNegNum[i]);
  }

  Plaintext Pcheck;
  decryptor2.decrypt(CposNum, Pcheck); //解密
  vector<double> vecCheck;
  encoder2.decode(Pcheck, vecCheck); //解码
  cout << "CposNum计算结果 ......." << endl;
  print_vector(vecCheck, TboxNum, 12);

  //vector<double> posNum = {}; //处理的向量分量数就是所有特征的分箱数之和
  vector<double> Pg = {}; //g_i的明文数据,用于明文方式计算结果比对//

  for (int i = 0; i < feaNum; i++) //展开所有特征的分箱分量，依次排好
  {
    for (int j = 0; j < SposNum[i].size(); j++)
    {
      //posNum.push_back(SposNum[i][j]);
      Pg.push_back(SposNum[i][j] / TposNum[i] - 1);
    }
  }

  //vector<double> negNum = {}; //处理的向量分量数就是所有特征的分箱数之和
  vector<double> Pb = {}; //b_i的明文数据,用于明文方式计算结果比对

  for (int i = 0; i < feaNum; i++)
  {
    for (int j = 0; j < SnegNum[i].size(); j++)
    {
      //negNum.push_back(SnegNum[i][j]);
      Pb.push_back(SnegNum[i][j] / TnegNum[i] - 1);
    }
  }

  //A对posNum和negNum进行加密发送给B

  /*
  //对向量posNum、negNum进行编码
  Plaintext PposNum, PnegNum;
  encoder2.encode(posNum, scale, PposNum);
  encoder2.encode(negNum, scale, PnegNum);

  //对明文PposNum、PnegNum进行加密
  Ciphertext CposNum, CnegNum;
  encryptor2.encrypt(PposNum, CposNum);
  encryptor2.encrypt(PnegNum, CnegNum);
*/

  //B对TposNum、TnegNum的倒数进行编码和加密
  //这里要注意编码的方式，不能对一个常数进行编码，因为常数直接进行编码是整个vector都是一个相同的数
  //这里先处理好每个特征对应分箱数的常数，然后将整个vector一起编码

  vector<double> InTposNum = {};
  vector<double> InTnegNum = {};

  for (int i = 0; i < feaNum; i++)
  {
    for (int j = 0; j < boxNum[i]; j++)
    {
      InTposNum.push_back(1 / TposNum[i]); //j个分箱都是相同的
      InTnegNum.push_back(1 / TnegNum[i]);
    }
  }

  //整体进行编码
  Plaintext PInTposNum, PInTnegNum;
  encoder2.encode(InTposNum, scale, PInTposNum);
  encoder2.encode(InTnegNum, scale, PInTnegNum);

  //对明文PInTposNum, PInTnegNum进行加密
  Ciphertext CInTposNum, CInTnegNum;
  encryptor2.encrypt(PInTposNum, CInTposNum);
  encryptor2.encrypt(PInTnegNum, CInTnegNum);

  //计算A_i=G_i/G_total-B_i/B_total的同态密文, 这里是10+10个分箱, 利用向量一次性计算
  //先做G_i和1/G_total, B_i和1/B_total乘法运算，再做它们的减法运算
  Ciphertext CG, CB;
  //密文相乘，要进行relinearize和rescaling操作

  evaluator2.multiply(CposNum, CInTposNum, CG);
  evaluator2.relinearize_inplace(CG, relin_keys2);
  evaluator2.rescale_to_next_inplace(CG);

  evaluator2.multiply(CnegNum, CInTnegNum, CB);
  evaluator2.relinearize_inplace(CB, relin_keys2);
  evaluator2.rescale_to_next_inplace(CB);

  //密文MG, MB在同一个level，可以直接做减法运算
  Ciphertext Csub;
  //密文相减, 不需要进行relinearize和rescaling操作
  evaluator2.sub(CG, CB, Csub);

  //现在计算g_i和b_i
  Ciphertext Cg, Cb; //Cg=CG-1, Cb=CB-1
  //vector<double> p = {1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0};
  Plaintext P1;
  encoder2.encode(1.0, scale, P1); //encode 1.0

  /*
  vector<double> result_p1;
  encoder2.decode(P1, result_p1);
  cout << "check encode!!" << endl;
  print_vector(result_p1, 20, 3);
*/

  Ciphertext CP1;
  encryptor2.encrypt(P1, CP1);
  evaluator2.square_inplace(CP1);
  evaluator2.relinearize_inplace(CP1, relin_keys2);
  evaluator2.rescale_to_next_inplace(CP1);

  //evaluator2.rescale_to_next_inplace(CP1);

  //把常数编码的parms_id转化到与密文的一致，这样才能相加减
  //parms_id_type CG_parms_id = CG.parms_id();
  //evaluator2.mod_switch_to_inplace(CP1, CG_parms_id);

  ios old_fmt(nullptr);
  old_fmt.copyfmt(cout);
  cout << fixed << setprecision(12);
  /*
  cout << " CP1 scale: " << CP1.scale() << endl;
  cout << " CG scale: " << CG.scale() << endl;
  cout << " CB scale: " << CB.scale() << endl;

 */

  //CP1和CG和CB的scale一致
  evaluator2.sub(CG, CP1, Cg);
  evaluator2.sub(CB, CP1, Cb);

  //现在计算泰勒展开式

  Ciphertext pdg[coeffNum], pdb[coeffNum]; //g_i and b_i的1次项计算
  //先把常数的parms_id设置正确，否则报错“encrypted_ntt and plain_ntt parameter mismatch”

  Ciphertext tempdg1, tempdb1;
  evaluator2.multiply(Cg, Csub, tempdg1); //both scale 1
  evaluator2.multiply(Cb, Csub, tempdb1);
  evaluator2.relinearize_inplace(tempdg1, relin_keys2);
  evaluator2.rescale_to_next_inplace(tempdg1);
  evaluator2.relinearize_inplace(tempdb1, relin_keys2);
  evaluator2.rescale_to_next_inplace(tempdb1);

  parms_id_type tempdg1_parms_id = tempdg1.parms_id();
  evaluator2.mod_switch_to_inplace(COEEF[0], tempdg1_parms_id);

  evaluator2.multiply_plain(tempdg1, COEEF[0], pdg[0]);
  evaluator2.multiply_plain(tempdb1, COEEF[0], pdb[0]);

  //乘以常数只需要rescale
  evaluator2.rescale_to_next_inplace(pdg[0]);
  evaluator2.rescale_to_next_inplace(pdb[0]);

  Ciphertext tempgbc2, dg2, db2; //g_i and b_i的2次项计算
  evaluator2.square(Cg, dg2);
  evaluator2.square(Cb, db2);
  //密文相乘，重线性化和rescale
  evaluator2.relinearize_inplace(dg2, relin_keys2);
  evaluator2.rescale_to_next_inplace(dg2);
  evaluator2.relinearize_inplace(db2, relin_keys2);
  evaluator2.rescale_to_next_inplace(db2);

  //dg2_parms_id和db2_parms_id相同，只设置1个即可
  parms_id_type Csub_parms_id = Csub.parms_id();
  evaluator2.mod_switch_to_inplace(COEEF[1], Csub_parms_id);

  evaluator2.multiply_plain(Csub, COEEF[1], tempgbc2); //same for g and b
  evaluator2.rescale_to_next_inplace(tempgbc2);

  evaluator2.multiply(tempgbc2, dg2, pdg[1]);
  evaluator2.multiply(tempgbc2, db2, pdb[1]);

  evaluator2.relinearize_inplace(pdg[1], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdg[1]);
  evaluator2.relinearize_inplace(pdb[1], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdb[1]);

  cout << "2 finished!" << endl;
  Ciphertext tpdg3, tpdb3; //g_i and b_i的3次项计算
  //复用tempdg1和tempdb1，dg2和db2
  evaluator2.multiply(dg2, tempdg1, tpdg3);
  evaluator2.multiply(db2, tempdb1, tpdb3);

  evaluator2.relinearize_inplace(tpdg3, relin_keys2);
  evaluator2.rescale_to_next_inplace(tpdg3);
  evaluator2.relinearize_inplace(tpdb3, relin_keys2);
  evaluator2.rescale_to_next_inplace(tpdb3);

  parms_id_type tpdg3_parms_id = tpdg3.parms_id();
  evaluator2.mod_switch_to_inplace(COEEF[2], tpdg3_parms_id);

  evaluator2.multiply_plain(tpdg3, COEEF[2], pdg[2]);
  evaluator2.multiply_plain(tpdb3, COEEF[2], pdb[2]);

  evaluator2.rescale_to_next_inplace(pdg[2]);
  evaluator2.rescale_to_next_inplace(pdb[2]);

  Ciphertext tempgbc4, uptemp, dg4, db4; //g_i and b_i的4次项计算
  evaluator2.square(dg2, dg4);
  evaluator2.square(db2, db4);

  evaluator2.relinearize_inplace(dg4, relin_keys2);
  evaluator2.rescale_to_next_inplace(dg4);
  evaluator2.relinearize_inplace(db4, relin_keys2);
  evaluator2.rescale_to_next_inplace(db4);

  parms_id_type Csub4_parms_id = Csub.parms_id();
  evaluator2.mod_switch_to_inplace(COEEF[3], Csub4_parms_id);

  evaluator2.multiply_plain(Csub, COEEF[3], tempgbc4); //same for g and b
  evaluator2.rescale_to_next_inplace(tempgbc4);

  //tempgbc4的level为2，不够dg4的level3， 将tempgbc4乘以明文1, 然后rescale
  parms_id_type tempgbc4_parms_id = tempgbc4.parms_id();
  evaluator2.mod_switch_to_inplace(P1, tempgbc4_parms_id);

  evaluator2.multiply_plain(tempgbc4, P1, uptemp); //更新tempgbc4
  evaluator2.rescale_to_next_inplace(uptemp);
  //现在level都为3，可以和dg4进行相乘了
  evaluator2.multiply(dg4, uptemp, pdg[3]);
  evaluator2.multiply(db4, uptemp, pdb[3]);

  evaluator2.relinearize_inplace(pdg[3], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdg[3]);
  evaluator2.relinearize_inplace(pdb[3], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdb[3]);

  cout << "4 finished!" << endl;

  Ciphertext tempgbc5, tempg52, tempb52, dg3, db3; //g_i and b_i的5次项计算

  parms_id_type Csub5_parms_id = Csub.parms_id();
  evaluator2.mod_switch_to_inplace(COEEF[4], Csub5_parms_id);

  evaluator2.multiply_plain(Csub, COEEF[4], tempgbc5); //same for g and b
  evaluator2.rescale_to_next_inplace(tempgbc5);

  //首先乘以x^2, rescale后变成level3，再和x^3相乘
  evaluator2.multiply(dg2, tempgbc5, tempg52);
  evaluator2.multiply(db2, tempgbc5, tempb52);

  evaluator2.relinearize_inplace(tempg52, relin_keys2);
  evaluator2.rescale_to_next_inplace(tempg52);
  evaluator2.relinearize_inplace(tempb52, relin_keys2);
  evaluator2.rescale_to_next_inplace(tempb52);

  cout << " 5 1 finished!" << endl;
  //计算dg3
  Ciphertext dg1, db1;
  parms_id_type Cg_parms_id = Cg.parms_id();
  Plaintext P1_5;
  encoder2.encode(1.0, scale, P1_5); //encode 1.0
  evaluator2.mod_switch_to_inplace(P1_5, Cg_parms_id);

  evaluator2.multiply_plain(Cg, P1_5, dg1);
  evaluator2.multiply_plain(Cb, P1_5, db1);
  evaluator2.rescale_to_next_inplace(dg1); //把x*1拉到和x^2同样的level上
  evaluator2.rescale_to_next_inplace(db1);

  evaluator2.multiply(dg1, dg2, dg3);
  evaluator2.multiply(db1, db2, db3);

  evaluator2.relinearize_inplace(dg3, relin_keys2);
  evaluator2.rescale_to_next_inplace(dg3);
  evaluator2.relinearize_inplace(db3, relin_keys2);
  evaluator2.rescale_to_next_inplace(db3);

  cout << " 5 2 finished!" << endl;

  //计算 pdg[4]
  evaluator2.multiply(tempg52, dg3, pdg[4]);
  evaluator2.multiply(tempb52, db3, pdb[4]);

  evaluator2.relinearize_inplace(pdg[4], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdg[4]);
  evaluator2.relinearize_inplace(pdb[4], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdb[4]);

  cout << "5 finished!" << endl;

  Ciphertext tempgbc6, tempg62, tempb62; //g_i and b_i的6次项计算

  parms_id_type Csub6_parms_id = Csub.parms_id();
  evaluator2.mod_switch_to_inplace(COEEF[5], Csub6_parms_id);

  evaluator2.multiply_plain(Csub, COEEF[5], tempgbc6); //same for g and b
  evaluator2.rescale_to_next_inplace(tempgbc6);

  //首先乘以x^2, rescale后变成level3，再和x^4相乘
  evaluator2.multiply(dg2, tempgbc6, tempg62);
  evaluator2.multiply(db2, tempgbc6, tempb62);

  evaluator2.relinearize_inplace(tempg62, relin_keys2);
  evaluator2.rescale_to_next_inplace(tempg62);
  evaluator2.relinearize_inplace(tempb62, relin_keys2);
  evaluator2.rescale_to_next_inplace(tempb62);

  evaluator2.multiply(dg4, tempg62, pdg[5]);
  evaluator2.multiply(db4, tempb62, pdb[5]);

  evaluator2.relinearize_inplace(pdg[5], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdg[5]);
  evaluator2.relinearize_inplace(pdb[5], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdb[5]);

  cout << "6 finished!" << endl;

  Ciphertext tempgbc7, dg7, db7;      //g_i and b_i的7次项计算
  evaluator2.multiply(dg3, dg4, dg7); //注意dg3和dg4处于同一个level上，可以相乘
  evaluator2.multiply(db3, db4, db7);
  evaluator2.relinearize_inplace(dg7, relin_keys2);
  evaluator2.rescale_to_next_inplace(dg7);
  evaluator2.relinearize_inplace(db7, relin_keys2);
  evaluator2.rescale_to_next_inplace(db7); //level 4

  parms_id_type Csub7_parms_id = Csub.parms_id();
  evaluator2.mod_switch_to_inplace(COEEF[6], Csub7_parms_id);

  evaluator2.multiply_plain(Csub, COEEF[6], tempgbc7); //same for g and b
  evaluator2.rescale_to_next_inplace(tempgbc7);        //level 2, update 2 times

  //连续乘以两次明文P1，进行rescale
  for (int i = 0; i < 2; i++)
  {
    Plaintext P1_7;
    encoder2.encode(1.0, scale, P1_7); //encode 1.0
    parms_id_type tempgbc7_parms_id = tempgbc7.parms_id();
    evaluator2.mod_switch_to_inplace(P1_7, tempgbc7_parms_id);

    evaluator2.multiply_plain_inplace(tempgbc7, P1_7); //更新tempgbc7
    evaluator2.rescale_to_next_inplace(tempgbc7);
  }

  //现在tempgbc7的level和dg7相同，可以相乘了
  evaluator2.multiply(dg7, tempgbc7, pdg[6]);
  evaluator2.multiply(db7, tempgbc7, pdb[6]);
  evaluator2.relinearize_inplace(pdg[6], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdg[6]);
  evaluator2.relinearize_inplace(pdb[6], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdb[6]);

  Ciphertext tempgbc8, dg8, db8; //g_i and b_i的8次项计算
  evaluator2.square(dg4, dg8);
  evaluator2.square(db4, db8);

  evaluator2.relinearize_inplace(dg8, relin_keys2);
  evaluator2.rescale_to_next_inplace(dg8);
  evaluator2.relinearize_inplace(db8, relin_keys2);
  evaluator2.rescale_to_next_inplace(db8); //level 4

  parms_id_type Csub8_parms_id = Csub.parms_id();
  evaluator2.mod_switch_to_inplace(COEEF[7], Csub8_parms_id);

  evaluator2.multiply_plain(Csub, COEEF[7], tempgbc8); //same for g and b
  evaluator2.rescale_to_next_inplace(tempgbc8);        //level 2, update 2 times

  //连续乘以两次明文P1，进行rescale
  for (int i = 0; i < 2; i++)
  {
    Plaintext P1_8;
    encoder2.encode(1.0, scale, P1_8); //encode 1.0

    parms_id_type tempgbc8_parms_id = tempgbc8.parms_id();
    evaluator2.mod_switch_to_inplace(P1_8, tempgbc8_parms_id);

    evaluator2.multiply_plain_inplace(tempgbc8, P1_8); //更新tempgbc8
    evaluator2.rescale_to_next_inplace(tempgbc8);
  }

  //现在tempgbc8的level和dg8相同，可以相乘了
  evaluator2.multiply(dg8, tempgbc8, pdg[7]);
  evaluator2.multiply(db8, tempgbc8, pdb[7]);

  evaluator2.relinearize_inplace(pdg[7], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdg[7]);
  evaluator2.relinearize_inplace(pdb[7], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdb[7]);

  cout << "8 finished!" << endl;

  Ciphertext mgP1, mbP1, tempgbc9, tempdg9, tempdb9; //g_i and b_i的9次项计算

  parms_id_type Csub9_parms_id = Csub.parms_id();
  evaluator2.mod_switch_to_inplace(COEEF[8], Csub9_parms_id);

  evaluator2.multiply_plain(Csub, COEEF[8], tempgbc9); //same for g and b
  evaluator2.rescale_to_next_inplace(tempgbc9);        //level 2

  //相乘x的level为2
  Plaintext P1_9_0;
  encoder2.encode(1.0, scale, P1_9_0); //encode 1.0

  parms_id_type Cg1_parms_id = Cg.parms_id();
  evaluator2.mod_switch_to_inplace(P1_9_0, Cg1_parms_id);

  evaluator2.multiply_plain(Cg, P1_9_0, mgP1);
  evaluator2.multiply_plain(Cb, P1_9_0, mbP1);
  evaluator2.rescale_to_next_inplace(mgP1);
  evaluator2.rescale_to_next_inplace(mbP1);

  //和tempgbc9相乘，level为3

  evaluator2.multiply(mgP1, tempgbc9, tempdg9);
  evaluator2.multiply(mbP1, tempgbc9, tempdb9);
  evaluator2.relinearize_inplace(tempdg9, relin_keys2);
  evaluator2.rescale_to_next_inplace(tempdg9);
  evaluator2.relinearize_inplace(tempdb9, relin_keys2);
  evaluator2.rescale_to_next_inplace(tempdb9); //level 3

  //提升level为4, 使得能和dg8相乘
  Plaintext P1_9_1;
  encoder2.encode(1.0, scale, P1_9_1); //encode 1.0
  parms_id_type tempdb9_parms_id = tempdb9.parms_id();
  evaluator2.mod_switch_to_inplace(P1_9_1, tempdb9_parms_id);

  evaluator2.multiply_plain_inplace(tempdg9, P1_9_1);
  evaluator2.multiply_plain_inplace(tempdb9, P1_9_1);
  evaluator2.rescale_to_next_inplace(tempdg9);
  evaluator2.rescale_to_next_inplace(tempdb9); //level 4

  //和dg8相乘
  evaluator2.multiply(dg8, tempdg9, pdg[8]);
  evaluator2.multiply(db8, tempdb9, pdb[8]);
  evaluator2.relinearize_inplace(pdg[8], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdg[8]);
  evaluator2.relinearize_inplace(pdb[8], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdb[8]); //level 5

  Ciphertext tempgbc10, tempdg10, tempdb10, dg10, db10; //g_i and b_i的10次项计算

  parms_id_type Csub10_parms_id = Csub.parms_id();
  evaluator2.mod_switch_to_inplace(COEEF[9], Csub10_parms_id);

  evaluator2.multiply_plain(Csub, COEEF[9], tempgbc10); //same for g and b
  evaluator2.rescale_to_next_inplace(tempgbc10);        //level 2

  //dg2和tempgbc10相乘，level为3

  evaluator2.multiply(dg2, tempgbc10, tempdg10);
  evaluator2.multiply(db2, tempgbc10, tempdb10);
  evaluator2.relinearize_inplace(tempdg10, relin_keys2);
  evaluator2.rescale_to_next_inplace(tempdg10);
  evaluator2.relinearize_inplace(tempdb10, relin_keys2);
  evaluator2.rescale_to_next_inplace(tempdb10); //level 3

  //提升level为4, 使得能和dg8相乘
  Plaintext P1_10;
  encoder2.encode(1.0, scale, P1_10); //encode 1.0
  parms_id_type tempdg10_parms_id = tempdg10.parms_id();
  evaluator2.mod_switch_to_inplace(P1_10, tempdg10_parms_id);

  evaluator2.multiply_plain_inplace(tempdg10, P1_10);
  evaluator2.multiply_plain_inplace(tempdb10, P1_10);
  evaluator2.rescale_to_next_inplace(tempdg10);
  evaluator2.rescale_to_next_inplace(tempdb10); //level 4

  //和dg8相乘
  evaluator2.multiply(dg8, tempdg10, pdg[9]);
  evaluator2.multiply(db8, tempdb10, pdb[9]);
  evaluator2.relinearize_inplace(pdg[9], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdg[9]);
  evaluator2.relinearize_inplace(pdb[9], relin_keys2);
  evaluator2.rescale_to_next_inplace(pdb[9]); //level 5

  //现在开始相加所有的单项式
  //首先输出所有单项式的level

  /*
  cout << "Modulus chain index for pdg1 to pdg10: " << endl;
  for (int i = 0; i < coeffNum; i++)
  {
    cout << " pdg " << i << " chain index" << context2.get_context_data(pdg[i].parms_id())->chain_index() << endl;
    cout << " pdb " << i << " chain index" << context2.get_context_data(pdb[i].parms_id())->chain_index() << endl;
  }
  cout << "pdg9 scale: " << pdg[8].scale() << endl;
  cout << "pdg10 scale: " << pdg[9].scale() << endl;
 */

  //现在设置参数，让这些不同level的单项式能够相加，需要设置scale和parms_id两个参数
  //设置全部的scale相同，并统一parms_id
  parms_id_type last_parms_id = pdg[9].parms_id();

  for (int i = 0; i < coeffNum; i++)
  {
    pdg[i].scale() = pow(2.0, 50);
    pdb[i].scale() = pow(2.0, 50);

    evaluator2.mod_switch_to_inplace(pdg[i], last_parms_id);
    evaluator2.mod_switch_to_inplace(pdb[i], last_parms_id);
  }

  Ciphertext encrypt_g, encrypt_b;

  evaluator2.add(pdg[0], pdg[1], encrypt_g); //把泰勒展开式的单项式相加
  evaluator2.add(pdb[0], pdb[1], encrypt_b);

  for (int i = 2; i < coeffNum; i++)
  {
    evaluator2.add_inplace(encrypt_g, pdg[i]);
    evaluator2.add_inplace(encrypt_b, pdb[i]);
  }

  //现在计算IV_i值
  Ciphertext IVi; //Csub_g_b=encrypt_g-encrypt_b, IVi=Csub*Csub_g_b
  evaluator2.sub(encrypt_g, encrypt_b, IVi);

  //现在计算该特征的整个IV值,密文上的向量分量求和运算需要旋转操作，分量1到分箱数求和，需要旋转向量后然后相加。

  Plaintext plain_IVi;
  cout << "Decrypt and decode IVi......" << endl;
  decryptor2.decrypt(IVi, plain_IVi);
  vector<double> result_IVi;
  encoder2.decode(plain_IVi, result_IVi);
  print_vector(result_IVi, TboxNum, 12);

  //根据每个特征的分箱数进行旋转和求和操作，把IVi值加起来
  Ciphertext Sum[feaNum];

  for (int i = 0; i < feaNum; i++)
  {
    const int rotNum = boxNum[i];
    Ciphertext rotated[rotNum];

    evaluator2.rotate_vector(IVi, 1, galois_keys2, rotated[0]);
    evaluator2.add(IVi, rotated[0], Sum[i]);

    for (int j = 1; j < rotNum - 1; j++) //注意这儿的左移次数，最大只需移动分箱-1次
    {
      evaluator2.rotate_vector(IVi, j + 1, galois_keys2, rotated[j]);
      evaluator2.add_inplace(Sum[i], rotated[j]);
    }
  }

  //对密文的IV进行对应分量的抽取,对密文的IV进行对应分量的抽取，
  //再进行多个特征IV的向量求和，这样可以一次性解密获得所有的IV值

  vector<double> extract[feaNum] = {};
  extract[0].push_back(1.0);

  int padding = 0;

  if (feaNum > 1)
  {
    for (int i = 1; i < feaNum; i++)
    {
      padding += boxNum[i - 1];

      for (int j = 0; j < padding; j++)
      {
        extract[i].push_back(0.0);
      }
      extract[i].push_back(1.0);
    }
  }

  Plaintext Pextract[feaNum];
  for (int i = 0; i < feaNum; i++)
  {
    encoder2.encode(extract[i], scale, Pextract[i]);
  }

  parms_id_type Sum_parms_id = Sum[0].parms_id(); //所有的Sum[I]的level都是相同的

  Ciphertext IV;

  cout << "here0!!!" << endl;

  //记录移位位置
  int shift[feaNum] = {0};
  shift[0] = 0;
  int shiftSum = 0;

  if (feaNum > 1)
  {
    for (int i = 1; i < feaNum; i++)
    {
      shiftSum += boxNum[i - 1];
      shift[i] = shiftSum - i; //紧接着上面一个IV值
    }
  }

  for (int i = 0; i < feaNum; i++)
  {

    evaluator2.mod_switch_to_inplace(Pextract[i], Sum_parms_id);
    evaluator2.multiply_plain_inplace(Sum[i], Pextract[i]);
    evaluator2.rescale_to_next_inplace(Sum[i]);
    //对Sum[i]进行相应位置的移位，保证所有特征的IV值排在密文向量的前面，方便解密后获取
    evaluator2.rotate_vector_inplace(Sum[i], shift[i], galois_keys2);
  }

  if (feaNum == 1)
  {
    IV = Sum[0];
  }
  else if (feaNum == 2)
  {
    evaluator2.add(Sum[0], Sum[1], IV);
  }
  else if (feaNum > 2)
  {
    evaluator2.add(Sum[0], Sum[1], IV);

    for (int i = 2; i < feaNum; i++)
    {
      evaluator2.add_inplace(IV, Sum[i]);
    }
  }

  cout << "Decrypt and decode  IV......" << endl;

  /*
  Plaintext Sum_plain_IV[feaNum];
  vector<double> Sum_result[feaNum];

  for (int i = 0; i < feaNum; i++)
  {
    cout << "IV value of index " << i << endl;
    decryptor2.decrypt(Sum[i], Sum_plain_IV[i]);
    encoder2.decode(Sum_plain_IV[i], Sum_result[i]);
    print_vector(Sum_result[i], TboxNum, 12);
  }
*/
  cout << "here!!!" << endl;
  //对提取后的IV进行解密
  Plaintext plainIV;
  vector<double> IvResult;
  decryptor2.decrypt(IV, plainIV);
  encoder2.decode(plainIV, IvResult);
  print_vector(IvResult, TboxNum, 12);

  cout << "here2!!!" << endl;

  //解密结果比对
  Plaintext plain_g, plain_b; //开始计算明文结果

  vector<double> A;
  for (int i = 0; i < TboxNum; i++)
  {
    A.push_back(Pg[i] - Pb[i]); //g-b=g-1-(b-1)
  }

  cout << "A_i*g_i预期结果:" << endl;
  vector<double> true_result_g;
  for (int i = 0; i < TboxNum; i++)
  {
    double x = Pg[i];
    double f = 0.4342944819 * x - 0.2171472409 * x * x + 0.1447648273 * pow(x, 3) - 0.1085736204 * pow(x, 4) +
               0.0868588963 * pow(x, 5) - 0.0723824136 * pow(x, 6) + 0.0620420688 * pow(x, 7) - 0.0542868102 * pow(x, 8) +
               0.0482549424 * pow(x, 9) - 0.0434294481 * pow(x, 10);
    true_result_g.push_back(f * A[i]);
  }
  print_vector(true_result_g, TboxNum, 12);

  decryptor2.decrypt(encrypt_g, plain_g); //解密
  vector<double> result_g;
  encoder2.decode(plain_g, result_g); //解码
  cout << "A_i*g_i计算结果 ......." << endl;
  print_vector(result_g, TboxNum, 12);

  cout << "A_i*b_i预期结果:" << endl;
  vector<double> true_result_b;
  for (int i = 0; i < TboxNum; i++)
  {
    double x = Pb[i];
    double f = 0.4342944819 * x - 0.2171472409 * x * x + 0.1447648273 * pow(x, 3) - 0.1085736204 * pow(x, 4) +
               0.0868588963 * pow(x, 5) - 0.0723824136 * pow(x, 6) + 0.0620420688 * pow(x, 7) - 0.0542868102 * pow(x, 8) +
               0.0482549424 * pow(x, 9) - 0.0434294481 * pow(x, 10);
    true_result_b.push_back(f * A[i]);
  }
  print_vector(true_result_b, TboxNum, 12);

  decryptor2.decrypt(encrypt_b, plain_b); //解密
  vector<double> result_b;
  encoder2.decode(plain_b, result_b); //解码
  cout << "A_i*b_i计算结果 ......." << endl;
  print_vector(result_b, TboxNum, 12);

  cout << "IV预期结果:" << endl;
  vector<double> true_result_IVi, temp;
  double Sum_Plain[feaNum] = {0.0};

  for (int i = 0; i < TboxNum; i++)
  {
    temp.push_back(true_result_g[i] - true_result_b[i]);
  }

  int index = -boxNum[0];

  for (int i = 0; i < feaNum; i++)
  {
    index += boxNum[i]; //第i个特征的IVi的求和index位于temp[index]处
    for (int j = 0; j < boxNum[i]; j++)
    {
      Sum_Plain[i] += temp[j + index];
    }

    cout << "IV value of feature index " << i << " is: " << Sum_Plain[i] << endl;
  }

  //结束计时
  auto end = std::chrono::steady_clock::now();
  std::chrono::duration<double> elapsed_seconds = end - start;
  std::cout << "CKKS计算耗费时间: " << elapsed_seconds.count() << "s\n";

  return 0;
}
