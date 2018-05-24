package main

import (
	"github.com/Nik-U/pbc"
	"fmt"
	"flag"
	"time"
	"math/big"
	mathrand "math/rand"
)

var Gt0 *pbc.Element
var Gt1 *pbc.Element
var GBigR *pbc.Element

type KeyPair struct {
	Sk SecretKey
	Tk TKey
	Vk VKey
}

type TransData struct {
	C0P *pbc.Element
	C1P *pbc.Element
}

type EncryptData struct {
	C0 *pbc.Element
	C1 *pbc.Element
	C2 []*pbc.Element
	C3 []*pbc.Element
	C4 []*pbc.Element
}

type SecretKey struct {
	Sk1       *pbc.Element
	SK2       *pbc.Element
	SK3       []*pbc.Element
	SK4       []*pbc.Element
	Attribute []*pbc.Element
}

type TKey struct {
	Tk1 *pbc.Element
	TK2 *pbc.Element
	TK3 []*pbc.Element
	TK4 []*pbc.Element
	t0        *pbc.Element
}

type VKey struct {
	Vk1 *pbc.Element
	VK2 *pbc.Element
	VK3 []*pbc.Element
	VK4 []*pbc.Element
	t1        *pbc.Element
}

func Paraminit(rbits, qbits uint32) (*pbc.Pairing, map[string]*pbc.Element) {

	params := pbc.GenerateA(rbits, qbits)
	pairing := params.NewPairing()
	publicPara := make(map[string]*pbc.Element, 6)

	publicPara["g"] = pairing.NewG1().Rand()
	publicPara["w"] = pairing.NewG1().Rand()
	publicPara["v"] = pairing.NewG1().Rand()
	publicPara["u"] = pairing.NewG1().Rand()
	publicPara["h"] = pairing.NewG1().Rand()

	return pairing, publicPara
}

func GenerateSecretKey(Psize uint, attributenum int, pairing *pbc.Pairing,
	parameters map[string]*pbc.Element) (SecretKey) {
	//we firstly generate the ramdom values.
	var thiskey SecretKey

	Attribute := make([]*pbc.Element, attributenum, attributenum)

	randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	ONE := pairing.NewZr().Set1()

	rZrlist := make([]*pbc.Element, attributenum, attributenum)

	thiskey.SK3 = make([]*pbc.Element, attributenum, attributenum)
	thiskey.SK4 = make([]*pbc.Element, attributenum, attributenum)

	alpha := new(big.Int).Rand(randsource, new(big.Int).Lsh(big.NewInt(1), Psize))

	alphaZr := pairing.NewZr().MulBig(ONE, alpha)

	for i := 0; i < len(Attribute); i++ {

		tmp := new(big.Int).Rand(randsource, new(big.Int).Lsh(big.NewInt(1), Psize))

		Attribute[i] = pairing.NewZr().MulBig(ONE, tmp)
	}

	for i, _ := range (rZrlist) {
		r := new(big.Int).Rand(randsource, new(big.Int).Lsh(big.NewInt(1), Psize))
		rZr := pairing.NewZr().MulBig(ONE, r)
		rZrlist[i] = rZr
	}
	r1 := new(big.Int).Rand(randsource, new(big.Int).Lsh(big.NewInt(1), Psize))
	bigr := pairing.NewZr().MulBig(ONE, r1)
	GBigR = bigr
	g := parameters["g"]
	w := parameters["w"]
	u := parameters["u"]
	h := parameters["h"]
	v := parameters["v"]

	//fixme, we update the e(g,g)^{alpha} here

	pairingalpha := pairing.NewGT().PowZn(pairing.NewGT().Pair(g, g), alphaZr)
	parameters["pairingalpha"] = pairingalpha

	thiskey.Sk1 = pairing.NewG1().Pow2Zn(g, alphaZr, w, bigr)
	thiskey.SK2 = pairing.NewG1().PowZn(g, bigr)

	for i := 0; i < len(rZrlist); i++ {
		thiskey.SK3[i] = pairing.NewG1().PowZn(g, rZrlist[i])
		uh := pairing.NewG1().Pow2Zn(u, Attribute[i], h, pairing.NewZr().Set1())
		thiskey.SK4[i] = pairing.NewG1().Pow2Zn(uh, rZrlist[i], v, pairing.NewZr().Neg(bigr))
	}
	thiskey.Attribute = Attribute
	return thiskey
}

func GenerateTranandVKey(Psize uint, pairing *pbc.Pairing, k int, SK SecretKey,
	parameters map[string]*pbc.Element) (TKey, VKey) {

	var myPuk TKey
	var myVk VKey
	randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	t0big := new(big.Int).Rand(randsource, new(big.Int).Lsh(big.NewInt(1), Psize))
	t1big := new(big.Int).Rand(randsource, new(big.Int).Lsh(big.NewInt(1), Psize))
	ONE := pairing.NewZr().Set1()
	t0 := pairing.NewZr().MulBig(ONE, t0big)
	t1 := pairing.NewZr().MulBig(ONE, t1big)
	Gt0 = t0
	Gt1 = t1
	myPuk.Tk1 = pairing.NewG1().PowZn(SK.Sk1, t0)
	myPuk.TK2 = pairing.NewG1().PowZn(SK.SK2, t0)
	myPuk.TK3 = make([]*pbc.Element, k, k)
	myPuk.TK4 = make([]*pbc.Element, k, k)

	myVk.Vk1 = pairing.NewG1().PowZn(myPuk.Tk1, t1)
	myVk.VK2 = pairing.NewG1().PowZn(myPuk.TK2, t1)
	myVk.VK3 = make([]*pbc.Element, k, k)
	myVk.VK4 = make([]*pbc.Element, k, k)

	for i := 0; i < k; i++ {
		myPuk.TK3[i] = pairing.NewG1().PowZn(SK.SK3[i], t0)
		myPuk.TK4[i] = pairing.NewG1().PowZn(SK.SK4[i], t0)
		myVk.VK3[i] = pairing.NewG1().PowZn(myPuk.TK3[i], t1)
		myVk.VK4[i] = pairing.NewG1().PowZn(myPuk.TK4[i], t1)

	}

	verfiy_keys(pairing, myPuk, myVk, parameters["g"], t1, k)

	myPuk.t0 = t0
	myVk.t1 = t1

	return myPuk, myVk

}

func Encryption(pairing *pbc.Pairing, parameters map[string]*pbc.Element,
	message *pbc.Element, key SecretKey, num int) (EncryptData,
	[]*pbc.Element, []*pbc.Element) {

	//msg := []byte(message)

	g := parameters["g"]
	w := parameters["w"]
	u := parameters["u"]
	h := parameters["h"]
	v := parameters["v"]
	alpha := parameters["pairingalpha"]

	//msgEl := pairing.NewZr().SetCompressedBytes(msg)
	//org := msgEl.CompressedBytes()

	uu := make([]*pbc.Element, num, num)
	vv := make([]*pbc.Element, num, num)

	secret := pairing.NewZr().Set0()
	for i := 0; i < num; i++ {
		uu[i] = pairing.NewZr().Rand()
		vv[i] = pairing.NewZr().Rand()
		secret = secret.ThenAdd(vv[i])
	}

	C2 := make([] *pbc.Element, num, num)
	C3 := make([] *pbc.Element, num, num)
	C4 := make([] *pbc.Element, num, num)

	C0 := pairing.NewGT().PowZn(alpha, secret).ThenMul(message)




	C1 := pairing.NewG1().PowZn(g, secret)

	for i := 0; i < num; i++ {
		C2[i] = pairing.NewG1().Mul(pairing.NewG1().PowZn(w, vv[i]), pairing.NewG1().PowZn(v,
			uu[i]))
		tmp := pairing.NewG1().Pow2Zn(u, key.Attribute[i], h, pairing.NewZr().Set1())
		C3[i] = pairing.NewG1().PowZn(tmp, pairing.NewZr().Neg(uu[i]))
		C4[i] = pairing.NewG1().PowZn(g, uu[i])
	}

	encrypt := EncryptData{
		C0,
		C1,
		C2,
		C3,
		C4,
	}
	return encrypt, uu, vv
}

func Transform(pairing *pbc.Pairing, parameters map[string]*pbc.Element, endata EncryptData,
	keypair KeyPair, k int, uu, vv []*pbc.Element) (TransData) {
	C1 := endata.C1
	TK := keypair.Tk
	VK := keypair.Vk

	above := pairing.NewGT().Pair(C1, TK.Tk1)
	above1 := pairing.NewGT().Pair(C1, VK.Vk1)

	output0 := pairing.NewGT().Set1()
	output1 := pairing.NewGT().Set1()
	for i := 0; i < k; i++ {

		first := pairing.NewGT().Pair(endata.C2[i], TK.TK2)
		second := pairing.NewGT().Pair(endata.C3[i], TK.TK3[i])
		third := pairing.NewGT().Pair(endata.C4[i], TK.TK4[i])

		first1 := pairing.NewGT().Pair(endata.C2[i], VK.VK2)
		second1 := pairing.NewGT().Pair(endata.C3[i], VK.VK3[i])
		third1 := pairing.NewGT().Pair(endata.C4[i], VK.VK4[i])

		result2 := pairing.NewGT().Mul(first1, second1).ThenMul(third1)

		//result := pairing.NewGT().Mul(tmpresult, first)
		result := pairing.NewGT().Mul(first, second).ThenMul(third)

		output0 = output0.ThenMul(result)
		output1 = output1.ThenMul(result2)
	}
	secret := pairing.NewZr().Set0()
	for _, el := range (vv) {
		secret.ThenAdd(el)
	}

	C0P := above.ThenDiv(output0)
	C1P := above1.ThenDiv(output1)
	egg := parameters["pairingalpha"]

	outfinal := pairing.NewGT().PowZn(egg, pairing.NewZr().Mul(Gt0, secret))
	if C0P.Equals(outfinal) {
		fmt.Println("pass the C0p check")
	} else {
		fmt.Println("fail the C0P check")
	}

	if C1P.Equals(pairing.NewGT().PowZn(outfinal, Gt1)) {
		fmt.Println("pass the C1P check")
	} else {
		fmt.Println("fail the C1P check")
	}

	encrypt := TransData{
		C0P,
		C1P,
	}

	return encrypt
}

func Verify(pairing *pbc.Pairing, data TransData, key VKey) {
	if data.C1P.Equals(pairing.NewGT().PowZn(data.C0P, key.t1)){
		fmt.Println("pass the key verfication")
	} else {
		fmt.Println("fail the key verification")
	}

}

func verfiy_keys(pairing *pbc.Pairing, tk TKey, vk VKey, g, t1 *pbc.Element, k int) {
	p1 := pairing.NewGT()
	p2 := pairing.NewGT()
	gt1 := pairing.NewG1().PowZn(g, t1)

	vk1 := vk.Vk1
	tk1 := tk.Tk1

	vk2 := vk.VK2
	tk2 := tk.TK2

	vk3 := vk.VK3
	tk3 := tk.TK3

	vk4 := vk.VK4
	tk4 := tk.TK4

	p1 = p1.Pair(vk1, g)
	p2 = p2.Pair(tk1, gt1)
	if (p1.Equals(p2) == false) {
		fmt.Println("error!!!!")
		return
	}

	p1 = p1.Pair(vk2, g)
	p2 = p2.Pair(tk2, gt1)
	if (p1.Equals(p2) == false) {
		fmt.Println("error!!!!")
		return
	}

	for i := 0; i < k; i++ {

		p1 = p1.Pair(vk3[i], g)
		p2 = p2.Pair(tk3[i], gt1)
		if (p1.Equals(p2) == false) {
			fmt.Println("error!!!!")
			return
		}
	}

	for i := 0; i < k; i++ {

		p1 = p1.Pair(vk4[i], g)
		p2 = p2.Pair(tk4[i], gt1)
		if (p1.Equals(p2) == false) {
			fmt.Println("error!!!!")
			return
		}
	}
	fmt.Println("pass the check")
	return
}

func Decrypt(pairing *pbc.Pairing,data EncryptData,trans TransData, key TKey)(*pbc.Element){
	C0 := data.C0
	t0 := key.t0
	C0P := trans.C0P

	//oOvert0 := pairing.NewZr().Div(pairing.NewZr().Set1(), t0)
	bottom := pairing.NewGT().PowZn(C0P, pairing.NewZr().Invert(t0))
	msg := pairing.NewGT().Div(C0, bottom)
	return msg


}


func play_test(pairing *pbc.Pairing) {

	a := pairing.NewZr().Rand()
	b := pairing.NewZr().Rand()
	c := pairing.NewZr().Rand()

	x := pairing.NewG1().Rand()
	y := pairing.NewG1().Rand()
	z := pairing.NewG1().Rand()

	first := pairing.NewG1().Pow2Zn(x, a, y, b)
	second := pairing.NewG1().PowZn(z, c)

	p1 := pairing.NewGT().Pair(first, second)

	ac := pairing.NewZr().Mul(a, c)
	bc := pairing.NewZr().Mul(b, c)

	first1 := pairing.NewG1().Pow2Zn(x, ac, y, bc)

	p2 := pairing.NewGT().Pair(first1, z)

	first2 := pairing.NewGT().Pair(pairing.NewG1().PowZn(x, a), pairing.NewG1().PowZn(z, c))
	second2 := pairing.NewGT().Pair(pairing.NewG1().PowZn(y, b), pairing.NewG1().PowZn(z, c))

	p3 := pairing.NewGT().Mul(first2, second2)

	//p1 = e(x^a*y^b,z^c)=e(x^(ac)*y^(bc),z)=e(x^a,z^c)*e(y^b,z^c)

	xa := pairing.NewG1().PowZn(x, a)
	yb := pairing.NewG1().PowZn(y, b)
	zc := pairing.NewG1().PowZn(z, c)

	first3 := pairing.NewG1().Add(xa, yb)

	p4 := pairing.NewGT().Pair(first3, zc)

	fmt.Println("===================")
	fmt.Println(p1)
	fmt.Println(p2)
	fmt.Println(p3)
	fmt.Println(p4)
	fmt.Println("===================")

	//e(x^a,y^b) = e(y^(-b),x^a)

	p5 := pairing.NewGT().Pair(pairing.NewG1().PowZn(x, a), pairing.NewG1().PowZn(y, b))

	p6 := pairing.NewGT().Pair(pairing.NewG1().PowZn(y, pairing.NewZr().Neg(b)),
		pairing.NewG1().PowZn(x, a))

	fmt.Println("===================")
	fmt.Println(p5)
	fmt.Println(p6)
	fmt.Println("===================")

	//e(a,b)*e(b,a^(-1)) = 1
	one := pairing.NewZr().Set1()
	baseg := pairing.NewG1().Rand()
	first4 := pairing.NewGT().Pair(xa, baseg)
	second4 := pairing.NewGT().Pair(baseg, pairing.NewG1().PowZn(xa, pairing.NewZr().Neg(one)))

	fmt.Println(pairing.NewGT().Mul(first4, second4))
	fmt.Println(pairing.NewGT().Pair(pairing.NewG1().Set1(), baseg))

	ax := pairing.NewG1().MulZn(x, a)
	by := pairing.NewG1().MulZn(y, b)

	o1 := pairing.NewGT().Pair(ax, by)

	o2 := pairing.NewGT().Pair(x, y)
	o2 = pairing.NewGT().PowZn(o2, pairing.NewZr().Mul(a, b))

	fmt.Println(o1)
	fmt.Println(o2)

	x_a := pairing.NewG1().PowZn(x, a)
	y_b := pairing.NewG1().PowZn(y, b)

	o3 := pairing.NewGT().Pair(x_a, y_b)
	o3p := pairing.NewGT().Pair(y_b, x_a)
	fmt.Println("o3", o3)
	fmt.Println("o3p", o3p)

	fmt.Println("---------")
	fmt.Println(ax)
	fmt.Println(x_a)






}

func main() {

	AttibuteNum := flag.Int("atrnum", 5, "Number of the attributes")
	Psize := flag.Int("ps", 1024, "the size of group P")
	flag.Parse()
	pairing, parameters := Paraminit(160, 512)

	//randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	//r1 := mathrand.New(randsource)

	mysecretkey := GenerateSecretKey(uint(*Psize), *AttibuteNum, pairing, parameters)

	Mypub, Myvkey := GenerateTranandVKey(uint(*Psize), pairing, *AttibuteNum, mysecretkey,
		parameters)

	mykeypair := KeyPair{
		mysecretkey,
		Mypub,
		Myvkey,
	}

	//fixme, we do not split the secret into matrix
	msg := pairing.NewGT().Rand()
	encryptodata, uu, vv := Encryption(pairing, parameters, msg, mykeypair.Sk, *AttibuteNum)

	transdata := Transform(pairing, parameters, encryptodata, mykeypair, *AttibuteNum, uu, vv)

	Verify(pairing, transdata, mykeypair.Vk)


	msgout := Decrypt(pairing, encryptodata, transdata, mykeypair.Tk)
	fmt.Println(msgout)


	fmt.Println("----------------ANSWER---------")
	fmt.Println("org:", msg.String())
	fmt.Println("recoverd: ", msgout.String())

	if msg.Equals(msgout){
		fmt.Println("Successfull")
	}else{
		fmt.Println("Protocol Failed")
	}

	fmt.Println("-------------------------------")
	//play_test(pairing)

}
