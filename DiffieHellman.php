<?php
/**
 * Created by PhpStorm.
 * User: hebingsong
 * Date: 2018/1/6
 * Time: 下午10:42
 */

/**
 * Class DiffieHellman
 *
 * 之前在讲密钥配送的时候，有提到 Diffie-Hellman 密钥交换，今天来简单的谈谈它。 Diffie-Hellman 密钥交换(Diffie-Hellman key exchange)通信双方仅通过交换一些可以公开的信息就能够生成共享的数字，而这一秘密数字就可以被用作对称密码的密钥。下面先来讲讲它的步骤。

Alice 向 Bob 发送两个质数 P 和 G
P 必须是一个非常大的质数，而 G 则是和 P 相关的数，被称为生成元，而 G 可以是一个很小的数。 P 和 G不需要保密。
Alice 生成一个随机数 A
A 是一个1 ~ P-2之间的整数，它只能是 Alice 自己知道的密码数字。
Bob 生成一个随机数 B
同样的，B 是一个1 ~ P-2之间的整数，它只能是 Bob 自己知道的密码数字。
Alice 将 G^A mod P 这个数发送给 Bob
这个数被 Eve 知道也没关系。
Bob 将 G^B mod P 这个数发送给 Alice
这个数被 Eve 知道也没关系。
Alice 用 Bob 发过来的数计算 A 次方 并求 mod P
即(G^B mod P)^A mode P，这个数就是共享密钥，可以将它简化为：G^(A*B) mod P
Bob 用 Alice 发过来的数计算 B 次方 并求 mod P
即(G^A mod P)^B mode P，这个数就是共享密钥，可以将它简化为：G^(A*B) mod P
我们可以发现：Alice 计算的密钥 = Bob 计算的密钥。 那么问题来了，Eve 能够计算出密钥么？从上面的步骤来看， Eve 知道P、G、G^A mod P、G^B mod P这 4 个数，而根据这 4 个数计算出共享秘钥 G^(A*B) mod P 是非常困难的，这个又是离散对数的问题了。

还是上篇博文《浅谈 RSA》说的时钟问题。我们假设 P 为 13，而 mod P 的时钟运算中所使用的数就是：0,1,2...12。我们看看下面 G^A mod P 表格（P = 13）。

G / A	1	2	3	4	5	6	7	8	9	10	11	12
0	0	0	0	0	0	0	0	0	0	0	0	0
1	1	1	1	1	1	1	1	1	1	1	1	1
2	2	4	8	3	6	12	11	9	5	10	7	1
3	3	9	1	3	9	1	3	9	1	3	9	1
4	4	3	12	9	10	1	4	3	12	9	10	1
5	5	12	8	1	5	12	8	1	5	2	8	1
6	6	10	8	9	2	12	7	3	5	4	11	1
7	7	10	5	9	11	12	6	3	8	4	2	1
9	8	12	5	1	8	12	5	1	8	12	5	1
9	9	3	1	9	3	1	9	3	1	9	3	1
10	10	9	12	3	4	1	10	9	12	3	4	1
11	11	4	5	3	7	12	2	9	8	10	6	1
12	12	1	12	1	12	1	12	1	12	1	12	1
在上表中，注意看 G 等于 2 那一行。

1
2
3
4
5
6
7
8
9
10
11
12
2^1  mod 13 = 2
2^2  mod 13 = 4
2^3  mod 13 = 7
2^4  mod 13 = 3
2^5  mod 13 = 6
2^6  mod 13 = 12
2^7  mod 13 = 11
2^8  mod 13 = 9
2^9  mod 13 = 5
2^10 mod 13 = 10
2^11 mod 13 = 7
2^12 mod 13 = 1
我们发现2^1到2^12这 12 个值都不一样，也就是说， 2 的乘方结果中出现了 1 到 12 的全部整数，由于 2 具备上述性质，因此称它为 13 的生成元，同样的， 6、7、11也是生成元。 P 的生成元的乘方结果与1 ~ P-1一一对应。正是因为这种一一对应关系， Alice 和 Bob 才能从1 ~ P-2中随机选择一个数字（之所以不能选择 P-1，因为G^(P-1) mod P的值一定是等于 1 的）。当然，从数学上看，我们还得必须证明对于任意质数 P 都一定存在生成元 G，但这个就不证明了。不得不感叹质数真的很神奇！！！
 */

class DiffieHellman
{
    private $is_prime = false;
    /**
     * @param int $bits
     *
     * @return array
     */
    public function generator(int $bits): array{
        // 生成min-max范围的数字
        $min = gmp_init(str_pad(1, $bits, 0), 2);
        $max = gmp_init(str_pad(1, $bits, 1), 2);

        return ['min' => $min, 'max' => $max, 'range' => $max-$min];
    }

    public function algo()
    {
        $range = $this->generator(64);
        while (1){
            if (!$this->is_prime){
                $p = gmp_random_range($range['min'], $range['max']);
                $prime = gmp_prob_prime($p, 100);
                if ($prime == 1){
                    $this->is_prime = true;
                }else{
                    unset($p);
                }
            }else{
                break;
            }
        }

        while(1){
            // 随机产生2- (p-1)的数值
            $g = gmp_strval(gmp_random_range(2, gmp_sub($p, 1)));
            // 假如 g^(p-1)mod(p) == 1 则g为生成元
            $pm = gmp_powm(gmp_strval($g), gmp_sub($p, 1), $p);

            if ($pm == 1){
                break;
            }

        }

        //用户A生成的随机数a
        $a = gmp_strval(gmp_random_range(2, gmp_sub($p, 2)));
        echo "userA 生成数值$a\n";
        // 用户B生成的随机数b
        $b = gmp_strval(gmp_random_range(2, gmp_sub($p, 2)));
        echo "userB 生成数值$b";
        $ga = gmp_powm($g, $a, $p);
        echo "g^(a)mod(p) = $ga\n";
        $gb = gmp_powm($g, $b, $p);
        echo "g^(b)mod(p) = $gb\n";
        $gab = gmp_powm($ga, $b, $p);
        echo "安全密钥=$gab\n";
    }
}

$dh = new DiffieHellman();

$dh->algo();