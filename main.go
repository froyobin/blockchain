package main

import (
	"github.com/Nik-U/pbc"
	"fmt"
	"flag"
	"time"
	"math/big"
	mathrand "math/rand"
)


type KeyPair struct{
	Sk  SecretKey
	Pk  PubKey
	Vk  VKey
	Attribute  []int
}


type EncryptData struct{

	C0  *pbc.Element
	C1  *pbc.Element
	C2  *pbc.Element
	C3  []*pbc.Element
	C4  *pbc.Element

}


type SecretKey struct{
	Sk1 *pbc.Element
	SK2 *pbc.Element
	SK3 []*pbc.Element
	SK4 []*pbc.Element
}


type PubKey struct{
	Tk1 *pbc.Element
	TK2 *pbc.Element
	TK3 []*pbc.Element
	TK4 []*pbc.Element
}

type VKey struct{
	Vk1 *pbc.Element
	VK2 *pbc.Element
	VK3 []*pbc.Element
	VK4 []*pbc.Element
}


func Paraminit(rbits,qbits uint32)(*pbc.Pairing, map[string]*pbc.Element){

	params := pbc.GenerateA(rbits, qbits)
	pairing := params.NewPairing()
	publicPara := make(map[string] *pbc.Element, 6)

	publicPara["g"] = pairing.NewG1().Rand()
	publicPara["w"] = pairing.NewG1().Rand()
	publicPara["v"] = pairing.NewG1().Rand()
	publicPara["u"] = pairing.NewG1().Rand()
	publicPara["h"] = pairing.NewG1().Rand()

	return pairing, publicPara
}


func GenerateSecretKey(Psize uint, attributenum int, pairing *pbc.Pairing,
	parameters map[string] *pbc.Element, AList []int)(SecretKey){
	//we firstly generate the ramdom values.
	var thiskey SecretKey

	randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	ONE := pairing.NewZr().Set1()


	rZrlist := make([]*pbc.Element, attributenum, attributenum)

	thiskey.SK3 = make([]*pbc.Element, attributenum, attributenum)
	thiskey.SK4 = make([]*pbc.Element, attributenum, attributenum)

	alpha := new(big.Int).Rand(randsource, new(big.Int).Lsh(big.NewInt(1), Psize))

	alphaZr := pairing.NewZr().MulBig(ONE, alpha)


	for i,_ := range(rZrlist) {
		r := new(big.Int).Rand(randsource, new(big.Int).Lsh(big.NewInt(1), Psize))
		rZr := pairing.NewZr().MulBig(ONE, r)
		rZrlist[i] = rZr
	}


	g := parameters["g"]
	w := parameters["w"]
	u := parameters["u"]
	h := parameters["h"]
	v := parameters["v"]

	//fixme, we update the e(g,g)^{alpha} here

	pairingalpha := pairing.NewGT().PowZn(pairing.NewGT().Pair(g,g), alphaZr)
	parameters["pairingalpha"] = pairingalpha


	thiskey.Sk1 = pairing.NewG1().Pow2Zn(g, alphaZr, w, rZrlist[0])
	thiskey.SK2 = pairing.NewG1().PowZn(g, rZrlist[0])





	for i:=1;i < len(rZrlist);i++ {

		thiskey.SK3[i] = pairing.NewG1().PowZn(g, rZrlist[i])
		ael := pairing.NewZr().Set1()
		if AList[i] == 1{
			ael = pairing.NewZr().Set1()
		}else{
			ael = pairing.NewZr().Set0()
		}
		uh := pairing.NewG1().Pow2Zn(u, ael, h, pairing.NewZr().Set1())
		uh =uh.PowZn(uh, rZrlist[i])
		thiskey.SK4[i] = pairing.NewG1().Pow2Zn(uh,rZrlist[i],v,
			pairing.NewZr().Neg(rZrlist[0]))
	}

	return thiskey
}

func GenerateTranandVKey(Psize uint, pairing *pbc.Pairing, k int, SK SecretKey)(PubKey, VKey){

	var myPuk PubKey
	var myVk VKey
	randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	t0big := new(big.Int).Rand(randsource, new(big.Int).Lsh(big.NewInt(1), Psize))
	t1big := new(big.Int).Rand(randsource, new(big.Int).Lsh(big.NewInt(1), Psize))
	ONE := pairing.NewZr().Set1()
	t0 := pairing.NewZr().MulBig(ONE, t0big)
	t1 := pairing.NewZr().MulBig(ONE, t1big)

	myPuk.Tk1 = pairing.NewG1().PowZn(SK.Sk1, t0)
	myPuk.TK2 = pairing.NewG1().PowZn(SK.SK2, t0)
	myPuk.TK3 = make([]*pbc.Element, k, k)
	myPuk.TK4 = make([]*pbc.Element, k, k)

	myVk.Vk1 = pairing.NewG1().PowZn(SK.Sk1, t0)
	myVk.VK2 = pairing.NewG1().PowZn(SK.SK2, t0)
	myVk.VK3 = make([]*pbc.Element, k, k)
	myVk.VK4 = make([]*pbc.Element, k, k)


	for i:=1;i < k; i++ {
		myPuk.TK3[i] = pairing.NewG1().PowZn(SK.SK3[i], t0)
		myPuk.TK4[i] = pairing.NewG1().PowZn(SK.SK4[i], t0)
		myVk.VK3[i] = pairing.NewG1().PowZn(SK.SK3[i], t1)
		myVk.VK4[i] = pairing.NewG1().PowZn(SK.SK4[i], t1)


	}

	return myPuk, myVk

}


func Encryption(pairing *pbc.Pairing,parameters map[string] *pbc.Element,
	secret *pbc.Element,message *pbc.Element, key SecretKey, attr []int)(EncryptData){

	//msg := []byte(message)

	g := parameters["g"]
	w := parameters["w"]
	u := parameters["u"]
	h := parameters["h"]
	v := parameters["v"]
	alpha := parameters["pairingalpha"]

	//msgEl := pairing.NewZr().SetCompressedBytes(msg)
	//org := msgEl.CompressedBytes()

	//fixme for simplicity we set the sum of u_i instead of the u_i
	usum := pairing.NewZr().Rand()


	C3 := make([] *pbc.Element,len(attr),len(attr))

	C0 := pairing.NewGT().PowZn(alpha, secret).ThenMulZn(message)
	C1 := pairing.NewG1().PowZn(g, secret)
	C2 := pairing.NewG1().Mul(pairing.NewG1().PowZn(w,secret), pairing.NewG1().PowZn(v, usum))



	ael := pairing.NewZr()
	for i:=0;i<len(attr);i++ {

		if attr[i] == 1 {
			ael = pairing.NewZr().Set1()
		} else {
			ael = pairing.NewZr().Set0()
		}

		C3_1 := pairing.NewG1().PowZn(u,ael).ThenMul(h)
		C3[i]= pairing.NewG1().PowZn(C3_1, pairing.NewZr().Neg(secret))
	}
	C4 := pairing.NewG1().PowZn(g, secret)

    encrypt := EncryptData{
    	C0,
    	C1,
    	C2,
    	C3,
    	C4,

	}
	return encrypt
}



func Transform(endata EncryptData, key VKey){




}

func main() {

	AttibuteNum := flag.Int("atrnum", 5, "Number of the attributes")
	Psize := flag.Int("ps", 1024, "the size of group P")
	flag.Parse()
	pairing, parameters := Paraminit(160,512)

	Attribute := make([]int, *AttibuteNum, *AttibuteNum)
	randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	r1 := mathrand.New(randsource)



	for i:=0;i<*AttibuteNum;i++{
		value := r1.Intn(2)

		Attribute[i] = value
	}

	mysecretkey := GenerateSecretKey(uint(*Psize), *AttibuteNum, pairing,
		parameters,
		Attribute)

	Mypub, Myvkey := GenerateTranandVKey(uint(*Psize), pairing, *AttibuteNum, mysecretkey)

	mykeypair := KeyPair{
		mysecretkey,
		Mypub,
		Myvkey,
		Attribute,
	}

	//fixme, we do not split the secret into matrix
	u := pairing.NewZr().Rand()
	msg := pairing.NewZr().SetBig(big.NewInt(12))
	encryptodata := Encryption(pairing,parameters, u,msg, mykeypair.Sk, Attribute)

	Transform(encryptodata, mykeypair.Vk)



    fmt.Println("thiskey",mysecretkey.SK4)
    fmt.Println("thiskey",mykeypair.Vk.VK4)
	fmt.Println(encryptodata.C0)




}
