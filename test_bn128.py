import time
from py_ecc import bn128, optimized_bn128
import random
print('Starting bn128 tests')

def randomInt():
    r = int(random.random()* lib.curve_order)
    return r
for lib in (bn128,optimized_bn128):
    FQ, FQ2, FQ12, field_modulus = lib.FQ, lib.FQ2, lib.FQ12, lib.field_modulus
    assert FQ(2) * FQ(2) == FQ(4)
    assert FQ(2) / FQ(7) + FQ(9) / FQ(7) == FQ(11) / FQ(7)
    assert FQ(2) * FQ(7) + FQ(9) * FQ(7) == FQ(11) * FQ(7)
    assert FQ(9) ** field_modulus == FQ(9)
    # print('FQ works fine')
    # st=time.time()
    # FQ(randomInt()) + FQ(randomInt())
    # print('FQ add',time.time()-st)
    # st=time.time()
    # FQ(randomInt()) * FQ(randomInt())
    # print('FQ multiply',time.time()-st)
    # st=time.time()
    # FQ(randomInt()) ** randomInt()
    # print('FQ exp',time.time()-st)
    # exit()    

    x = FQ2([1, 0])
    f = FQ2([1, 2])
    fpx = FQ2([2, 2])
    one = FQ2.one()
    assert x + f == fpx
    assert f / f == one
    assert one / f + x / f == (one + x) / f
    assert one * f + x * f == (one + x) * f
    assert x ** (field_modulus ** 2 - 1) == one
    # print('FQ2 works fine')
    # a=FQ2([randomInt(),randomInt()])
    # b=FQ2([randomInt(),randomInt()])
    # st=time.time()
    # a+b
    # print('FQ2 add',time.time()-st)
    # st=time.time()
    # a*b
    # print('FQ2 multiply',time.time()-st)
    # st=time.time()
    # a**randomInt()
    # print('FQ2 exp',time.time()-st)
    # exit()

    x = FQ12([1] + [0] * 11)
    f = FQ12([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    # f = FQ12([0] * 12)
    fpx = FQ12([2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    # g=x/f
    # print(g.coeffs[0])
    # print("x/f",x/f)
    print("f/x",f/x)
    exit()
    one = FQ12.one()
    assert x + f == fpx
    assert f / f == one
    assert one / f + x / f == (one + x) / f
    assert one * f + x * f == (one + x) * f
    # This check takes too long
    # assert x ** (field_modulus ** 12 - 1) == one
    print('FQ12 works fine')

    G1, G2, G12, b, b2, b12, is_inf, is_on_curve, eq, add, double, curve_order, multiply = \
      lib.G1, lib.G2, lib.G12, lib.b, lib.b2, lib.b12, lib.is_inf, lib.is_on_curve, lib.eq, lib.add, lib.double, lib.curve_order, lib.multiply
    if lib == optimized_bn128:
        g11=(FQ(9121282642809701931333593728297233225556711250127745709186816755779879923737),FQ(8783642022119951289582979607207867126556038468480503109520224385365741455513),FQ(1))
        is_on_curve(g11,b)
        g12=(FQ(19430493116922072356830709910231609246608721301711710668649991649389881488730),FQ(4110959498627045907440291871300490703579626657177845575364169615082683328588),FQ(1))
        is_on_curve(g12,b)
        expect_g=(FQ(17981918273786386398769813244173616322667195802888989780909050086192926768907),FQ(18658404630663819378315425423756597890713010608083111245835977740656931644247),FQ(1))
        print("==========g1 add from sololidity",eq(add(g11,g12),expect_g))
    # print(type(G1))
    # print(G1)
    # print(G2)
    # print(multiply(G1, 2))
    print(add(multiply(G1, 9), multiply(G1, 5)))
    assert eq(add(add(double(G1), G1), G1), double(double(G1)))
    assert not eq(double(G1), G1)
    assert eq(add(multiply(G1, 9), multiply(G1, 5)), add(multiply(G1, 12), multiply(G1, 2)))
    assert is_inf(multiply(G1, curve_order))
    print('G1 works fine')
    # print(G2)
    st=time.time()
    # print(multiply(G2, 9))
    multiply(G2, randomInt())
    print(time.time()-st)


    st=time.time()
    # print(multiply(G2, 9))
    multiply(G2, int(random.random()*100000))
    print(time.time()-st)
    # exit()
    print('FQ2 works fine')
    N=1
    a=multiply(G1, randomInt())
    b=multiply(G1, randomInt())
    # st=time.time()
    # for i in range(0, N):        
    #     add(a,b)
    # print('G1 add',(time.time()-st)/N)
    # st=time.time()
    # for i in range(0, N):        
    #     multiply(a,randomInt())
    # print('G1 multiply',(time.time()-st)/N)
        # st=time.time()
        # multiply(a,randomInt())
        # print('G1 multiply',time.time()-st)
        # exit()

    # a=multiply(G2, randomInt())
    # b=multiply(G2, randomInt())
    # c=multiply(G2, randomInt())
    # d=multiply(G2, randomInt())
    # st=time.time()
    # for i in range(0, N):        
    #     add(c,d)
    # print('G2 add',(time.time()-st)/N)
    # st=time.time()
    # for i in range(0, N):        
    #     multiply(c,randomInt())
    # print('G2 multiply',(time.time()-st)/N)
    

    # st=time.time()
    # for i in range(0, N):        
    #     # print(c,a)
    #     lib.pairing(c, a)
    # print('pairing',(time.time()-st)/N)

    

    a=multiply(G12, randomInt())
    b=multiply(G12, randomInt())
    st=time.time()
    for i in range(0, N):        
        add(a,b)
    print('G12 add',(time.time()-st)/N)
    st=time.time()
    for i in range(0, N):        
        multiply(a,randomInt())
    print('G12 multiply',(time.time()-st)/N)


    # exit()

    assert eq(add(add(double(G2), G2), G2), double(double(G2)))
    assert not eq(double(G2), G2)
    assert eq(add(multiply(G2, 9), multiply(G2, 5)), add(multiply(G2, 12), multiply(G2, 2)))
    assert is_inf(multiply(G2, curve_order))
    assert not is_inf(multiply(G2, 2 * field_modulus - curve_order))
    assert is_on_curve(multiply(G2, 9), b2)
    print('G2 works fine')
    print(field_modulus)
    print(curve_order)
    print(G12)
    print(double(G12))
    print(add(G12,G12))

    # exit()
    assert eq(add(add(double(G12), G12), G12), double(double(G12)))
    assert not eq(double(G12), G12)
    assert eq(add(multiply(G12, 9), multiply(G12, 5)), add(multiply(G12, 12), multiply(G12, 2)))
    assert is_on_curve(multiply(G12, 9), b12)
    assert is_inf(multiply(G12, curve_order))
    print('G12 works fine')

    pairing, neg = lib.pairing, lib.neg

    print('Starting pairing tests')
    a = time.time()
    p1 = pairing(G2, G1)
    pn1 = pairing(G2, neg(G1))
    print(p1)
    print(pn1)
    print(FQ12.one())
    print(int(p1.coeffs[0])*int(pn1.coeffs[0]) % curve_order)
    print(int(p1.coeffs[0])*int(pn1.coeffs[0]) % field_modulus)
    print(int(p1.coeffs[0])*int(pn1.coeffs[0]) % (field_modulus-1))
    assert p1 * pn1 == FQ12.one()
    print('Pairing check against negative in G1 passed')
    exit()
    np1 = pairing(neg(G2), G1)
    assert p1 * np1 == FQ12.one()
    assert pn1 == np1
    print('Pairing check against negative in G2 passed')
    assert p1 ** curve_order == FQ12.one()
    print('Pairing output has correct order')
    p2 = pairing(G2, multiply(G1, 2))
    assert p1 * p1 == p2
    print('Pairing bilinearity in G1 passed')
    assert p1 != p2 and p1 != np1 and p2 != np1
    print('Pairing is non-degenerate')
    po2 = pairing(multiply(G2, 2), G1)
    assert p1 * p1 == po2
    print('Pairing bilinearity in G2 passed')
    p3 = pairing(multiply(G2, 27), multiply(G1, 37))
    po3 = pairing(G2, multiply(G1, 999))
    assert p3 == po3
    print('Composite check passed')
    print('Total time for pairings: %.3f' % (time.time() - a))

