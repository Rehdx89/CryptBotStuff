//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class idk extends GhidraScript {
		
	public void run() throws Exception {
		int j = 0;
		int sz = 0xC4400;
		int offset = 0x402178;
		int offset2 = 0x40211c;
		byte bytesToDecrypt[] = getBytes(toAddr(offset), sz);
		byte key[] = getBytes(toAddr(offset2), 0xe0);

		for(int i = 0; i < sz; i++)
		{
			if(i % 3 == 0)
			{
				for(int k = 0; k < 0xff; k++)
				{
					bytesToDecrypt[i] = (byte)(k ^ (int)bytesToDecrypt[i]);		
				}
	
				if(j == 0x1e)
				{
					bytesToDecrypt[i] = (byte)((int)key[0] ^ (int)bytesToDecrypt[i]);	
					j = 0;
				}
				else
				{	
					j = j + 1;
					bytesToDecrypt[i] = (byte)((int)key[j] ^ (int)bytesToDecrypt[i]);	
				}
					
				bytesToDecrypt[i] = (byte)(0xf ^ (int)bytesToDecrypt[i]);	
		
				setByte(toAddr(offset), bytesToDecrypt[i]);
			}
			
			offset = offset + 1;
		}
	}
}
