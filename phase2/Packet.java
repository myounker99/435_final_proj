package Phase2;

import java.math.BigInteger;

public class Packet {
	
	BigInteger encryptMsg, encryptDS, encryptKs, hashBase;
	
	Packet(BigInteger encryptMsg, BigInteger encryptDS, BigInteger encryptKs, BigInteger hashBase)
	{
		this.encryptMsg = encryptMsg;
		this.encryptDS = encryptDS;
		this.encryptKs = encryptKs;
		this.hashBase = hashBase;				//this is to make the hashing algs the same. If this were being used in IRL, we would use something like SHA1 (which the receiver already knows)
	}

	public BigInteger getCipher() {
		
		return encryptKs;
	}

	public void setCipher(BigInteger add) {
		this.encryptKs = encryptKs.add(add);
	}
	
	public BigInteger getEMsg()
	{
		return this.encryptMsg;	
	}
	
	public BigInteger getEDS()
	{
		return this.encryptDS;
	}
	
	public BigInteger getEKs()
	{
		return this.encryptKs;
	}
	
	public BigInteger getHashBase()
	{
		return this.hashBase;
	}
	

}
