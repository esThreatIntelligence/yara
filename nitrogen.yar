rule Nitrogen_DLL_Sideloading {

	meta:
		author = "RussianPanda"
		description = "Nitrogen malicious DLL Side-loading Detection"

	strings:
		$p1 = "AVNitrogenStager"
		$p2 = "AVMsfPythonStager"
		$p3 = {65 4E 6F 39 54 30 31 4C 78 44 41 51 50 54 65 2F 6F 72 66 4F 59 44 61 73 55 76 65 77 57 45 48 45 67 34 67 49 72 6A 63 52 61 64 4E 78 74 7A 52 4E 51 69 61 72 56 66 47}
		$p4 = {68 69 6a 61 63 6b 69 6e 67 5f 65 6e 74 72 79}
	condition:
		uint16(0) == 0x5A4D and 2 of ($p*)
		
}

