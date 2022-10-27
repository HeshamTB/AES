#  ============================================================================
#  Name           : EE495
#  Description    : DES Encryption and Decryption Algorithm
#  ============================================================================


from tkinter import  *
from tkinter.scrolledtext import ScrolledText
from tkinter import ttk
from kauaes import AES, AESRound
import rsa
import MillerRabin as mr


T = Tk()
T.geometry("1300x700")
T.title("Encryption Algorithms")
#T.configure()

tabControl = ttk.Notebook(T)
#tab_des = ttk.Frame(tabControl)
tab_des = Frame(tabControl, background='lightblue')
tab_aes = Frame(tabControl, background='lightblue')
tab_rc4 = Frame(tabControl, background='lightblue')
tab_rsa = Frame(tabControl, background='lightblue')

tabControl.add(tab_des, text='DES')
tabControl.add(tab_aes, text='AES')
tabControl.add(tab_rc4, text='RC4')
tabControl.add(tab_rsa, text='RSA')

tabControl.pack(expand=1, fill='both')

plainText = StringVar()
cipherText = StringVar()
mainKey = StringVar()


#================================== DEFINE THE CLEAR FUNCTIONS HERE ==========================

def clear1():
    plainText.delete(1.0,END)

def clear2():
    cipherText.delete(1.0,END)

#=============================================================================================


hexa_to_bin = {
                '0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100',
                '5': '0101', '6': '0110', '7': '0111', '8': '1000', '9': '1001',
                'a': '1010', 'b': '1011', 'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'
               }


hexa_to_char = {
                '61': 'a', '62': 'b', '63': 'c', '64': 'd', '65': 'e', '66': 'f', '67': 'g', '68': 'h', '69':'i',
                '6a':'j', '6b':'k', '6c':'l', '6d':'m', '6e':'n', '6f':'o', '70':'p', '71':'q', '72':'r', '73':'s',
                '74':'t', '75':'u', '76':'v', '77':'w', '78':'x', '79':'y', '7a':'z', '41':'A', '42':'B', '43':'C',
                '44':'D', '45':'E', '46':'F', '47':'G', '48':'H', '49':'I', '4a':'J', '4b':'K', '4c':'L', '4d':'M', '4e':'N',
                '4f':'O', '50':'P', '51':'Q', '52':'R', '53':'S', '54':'T', '55':'U', '56':'V', '57':'W', '58':'X', '59':'Y', '5a':'Z'
               }



Sboxes = [

        {
    
            '000000':'1110', '000010':'0100', '000100':'1101', '000110':'0001', '001000':'0010', '001010':'1111', '001100':'1011', '001110':'1000',
            '010000':'0011', '010010':'1010', '010100':'0110', '010110':'1100', '011000':'0101', '011010':'1001', '011100':'0000', '011110':'0111',
            '000001':'0000', '000011':'1111', '000101':'0111', '000111':'0100', '001001':'1110', '001011':'0010', '001101':'1101', '001111':'0001',
            '010001':'1010', '010011':'0110', '010101':'1100', '010111':'1011', '011001':'1001', '011011':'0101', '011101':'0011', '011111':'1000',
            '100000':'0100', '100010':'0001', '100100':'1110', '100110':'1000', '101000':'1101', '101010':'0110', '101100':'0010', '101110':'1011',
            '110000':'1111', '110010':'1100', '110100':'1001', '110110':'0111', '111000':'0011', '111010':'1010', '111100':'0101', '111110':'0000',
            '100001':'1111', '100011':'1100', '100101':'1000', '100111':'0010', '101001':'0100', '101011':'1001', '101101':'0001', '101111':'0111',
            '110001':'0101', '110011':'1011', '110101':'0011', '110111':'1110', '111001':'1010', '111011':'0000', '111101':'0110', '111111':'1101'
            
        },

        {
    
            '000000':'1111', '000010':'0001', '000100':'1000', '000110':'1110', '001000':'0110', '001010':'1011', '001100':'0011', '001110':'0100',
            '010000':'1001', '010010':'0111', '010100':'0010', '010110':'1101', '011000':'1100', '011010':'0000', '011100':'0101', '011110':'1010',
            '000001':'0011', '000011':'1101', '000101':'0100', '000111':'0111', '001001':'1111', '001011':'0010', '001101':'1000', '001111':'1110',
            '010001':'1100', '010011':'0000', '010101':'0001', '010111':'1010', '011001':'0110', '011011':'1001', '011101':'1011', '011111':'0101',
            '100000':'0000', '100010':'1110', '100100':'0111', '100110':'1011', '101000':'1010', '101010':'0100', '101100':'1101', '101110':'0001',
            '110000':'0101', '110010':'1000', '110100':'1100', '110110':'0110', '111000':'1001', '111010':'0011', '111100':'0010', '111110':'1111',
            '100001':'1101', '100011':'1000', '100101':'1010', '100111':'0001', '101001':'0011', '101011':'1111', '101101':'0100', '101111':'0010',
            '110001':'1011', '110011':'0110', '110101':'0111', '110111':'1100', '111001':'0000', '111011':'0101', '111101':'1110', '111111':'1001'
            
        },

        {
    
            '000000':'1010', '000010':'0000', '000100':'1001', '000110':'1110', '001000':'0110', '001010':'0011', '001100':'1111', '001110':'0101',
            '010000':'0001', '010010':'1101', '010100':'1100', '010110':'0111', '011000':'1011', '011010':'0100', '011100':'0010', '011110':'1000',
            '000001':'1011', '000011':'0111', '000101':'0000', '000111':'1001', '001001':'0011', '001011':'0100', '001101':'0110', '001111':'1010',
            '010001':'0010', '010011':'1000', '010101':'0101', '010111':'1110', '011001':'1100', '011011':'1011', '011101':'1111', '011111':'0001',
            '100000':'1101', '100010':'0110', '100100':'0100', '100110':'1001', '101000':'1000', '101010':'1111', '101100':'0011', '101110':'0000',
            '110000':'1011', '110010':'0001', '110100':'0010', '110110':'1100', '111000':'0101', '111010':'1010', '111100':'1110', '111110':'0111',
            '100001':'0001', '100011':'1010', '100101':'1011', '100111':'0000', '101001':'0110', '101011':'1001', '101101':'1000', '101111':'0111',
            '110001':'0100', '110011':'1111', '110101':'1110', '110111':'0011', '111001':'1011', '111011':'0101', '111101':'0010', '111111':'1100'
            
        },

        {
    
            '000000':'0111', '000010':'1101', '000100':'1110', '000110':'0011', '001000':'0000', '001010':'0110', '001100':'1001', '001110':'1010',
            '010000':'0001', '010010':'0010', '010100':'1000', '010110':'0101', '011000':'1011', '011010':'1100', '011100':'0100', '011110':'1111',
            '000001':'1101', '000011':'1000', '000101':'1101', '000111':'0101', '001001':'0110', '001011':'1111', '001101':'0000', '001111':'0011',
            '010001':'0100', '010011':'0111', '010101':'0010', '010111':'1100', '011001':'0001', '011011':'1010', '011101':'1110', '011111':'1001',
            '100000':'1010', '100010':'0110', '100100':'1001', '100110':'0000', '101000':'1100', '101010':'1011', '101100':'0111', '101110':'1101',
            '110000':'1111', '110010':'0001', '110100':'0011', '110110':'1101', '111000':'0101', '111010':'0010', '111100':'1000', '111110':'0100',
            '100001':'0011', '100011':'1111', '100101':'0000', '100111':'0110', '101001':'1010', '101011':'0001', '101101':'1101', '101111':'1000',
            '110001':'1001', '110011':'0100', '110101':'0101', '110111':'1011', '111001':'1100', '111011':'0111', '111101':'0010', '111111':'1110'
            
        },

        {
    
            '000000':'0010', '000010':'1100', '000100':'0100', '000110':'0001', '001000':'0111', '001010':'1010', '001100':'1011', '001110':'0110',
            '010000':'1000', '010010':'0101', '010100':'0011', '010110':'1111', '011000':'1101', '011010':'0000', '011100':'1110', '011110':'1001',
            '000001':'1110', '000011':'1011', '000101':'0010', '000111':'1100', '001001':'0100', '001011':'0111', '001101':'1101', '001111':'0001',
            '010001':'0101', '010011':'0000', '010101':'1111', '010111':'1010', '011001':'0011', '011011':'1001', '011101':'1000', '011111':'0110',
            '100000':'0100', '100010':'0010', '100100':'0001', '100110':'1011', '101000':'1010', '101010':'1101', '101100':'0111', '101110':'1000',
            '110000':'1111', '110010':'1001', '110100':'1100', '110110':'0101', '111000':'0110', '111010':'0011', '111100':'0000', '111110':'0100',
            '100001':'1011', '100011':'1000', '100101':'1100', '100111':'0111', '101001':'0001', '101011':'1110', '101101':'0010', '101111':'1101',
            '110001':'0110', '110011':'1111', '110101':'0000', '110111':'1001', '111001':'1010', '111011':'0100', '111101':'0101', '111111':'0011'
            
        },

        {
    
            '000000':'1100', '000010':'0001', '000100':'1010', '000110':'1111', '001000':'1001', '001010':'0010', '001100':'0110', '001110':'1000',
            '010000':'0000', '010010':'1101', '010100':'0011', '010110':'0100', '011000':'1110', '011010':'0111', '011100':'0101', '011110':'1011',
            '000001':'1010', '000011':'1111', '000101':'0100', '000111':'0010', '001001':'0111', '001011':'1100', '001101':'1001', '001111':'0101',
            '010001':'0110', '010011':'0001', '010101':'1101', '010111':'1110', '011001':'0000', '011011':'1011', '011101':'0011', '011111':'1000',
            '100000':'1001', '100010':'1110', '100100':'1111', '100110':'0101', '101000':'0010', '101010':'1000', '101100':'1100', '101110':'0011',
            '110000':'0111', '110010':'0000', '110100':'0100', '110110':'1010', '111000':'0001', '111010':'1101', '111100':'1011', '111110':'0110',
            '100001':'0100', '100011':'0011', '100101':'0010', '100111':'1100', '101001':'1001', '101011':'0101', '101101':'1111', '101111':'1010',
            '110001':'1011', '110011':'1110', '110101':'0001', '110111':'0111', '111001':'0110', '111011':'0000', '111101':'1000', '111111':'1101'
            
        },

        {
    
            '000000':'0100', '000010':'1011', '000100':'0010', '000110':'1110', '001000':'1111', '001010':'0000', '001100':'1000', '001110':'1101',
            '010000':'0011', '010010':'1100', '010100':'1001', '010110':'0111', '011000':'0101', '011010':'1010', '011100':'0110', '011110':'0001',
            '000001':'1101', '000011':'0000', '000101':'1011', '000111':'0111', '001001':'0100', '001011':'1001', '001101':'0001', '001111':'1010',
            '010001':'1110', '010011':'0011', '010101':'0101', '010111':'1100', '011001':'0010', '011011':'1111', '011101':'1000', '011111':'0110',
            '100000':'0001', '100010':'0100', '100100':'1011', '100110':'1101', '101000':'1100', '101010':'0011', '101100':'0111', '101110':'1110',
            '110000':'1010', '110010':'1111', '110100':'0110', '110110':'1000', '111000':'0000', '111010':'0101', '111100':'1001', '111110':'0010',
            '100001':'0110', '100011':'1011', '100101':'1101', '100111':'1000', '101001':'0001', '101011':'0100', '101101':'1010', '101111':'0111',
            '110001':'1001', '110011':'0101', '110101':'0000', '110111':'1111', '111001':'1110', '111011':'0010', '111101':'0011', '111111':'1100'
            
        },

        {
    
            '000000':'1101', '000010':'0010', '000100':'1000', '000110':'0100', '001000':'0110', '001010':'1111', '001100':'1011', '001110':'0001',
            '010000':'1010', '010010':'1001', '010100':'0011', '010110':'1110', '011000':'0101', '011010':'0000', '011100':'1100', '011110':'0111',
            '000001':'0001', '000011':'1111', '000101':'1101', '000111':'1000', '001001':'1010', '001011':'0011', '001101':'0111', '001111':'0100',
            '010001':'1100', '010011':'0101', '010101':'0110', '010111':'1011', '011001':'0000', '011011':'1110', '011101':'1001', '011111':'0010',
            '100000':'0111', '100010':'1011', '100100':'0100', '100110':'0001', '101000':'1001', '101010':'1100', '101100':'1110', '101110':'0010',
            '110000':'0000', '110010':'0110', '110100':'1010', '110110':'1101', '111000':'1111', '111010':'0011', '111100':'0101', '111110':'1000',
            '100001':'0010', '100011':'0001', '100101':'1110', '100111':'0111', '101001':'0100', '101011':'1010', '101101':'1000', '101111':'1101',
            '110001':'1111', '110011':'1100', '110101':'1001', '110111':'0000', '111001':'0011', '111011':'0101', '111101':'0110', '111111':'1011'
            
        },

          ]



def Encrypt():

    #====================== Key Processing ===========================================

    initialKey = mainKey.get().lower()

    if len(initialKey) < 16 or len(initialKey) > 16:
        print("Please, enter 64 bits or 8 bytes as initial key ")
    else:
        byteKey = initialKey.encode('utf-8')
        hexaKey   = str(initialKey)
        print("The hexadecimal representational for your key is: \n")
        print(hexaKey, "\n")
        tempKey   = []
        s         = ""
        for i in str(hexaKey):
            for j in hexa_to_bin:
                if i == j:
                    tempKey.append(hexa_to_bin[j])
        binKey  = s.join(tempKey)
        print("The binary representational for your key is: \n")
        print(binKey,"\n")

        #==============================================================================


        #========== process key bits on a permutation array of 56 values ================

        PC1 = [
              57,   49,    41,   33,    25,    17,    9,
               1,   58,    50,   42,    34,    26,   18,
              10,    2,    59,   51,    43,    35,   27,
              19,   11,     3,   60,    52,    44,   36,
              63,   55,    47,   39,    31,    23,   15,
               7,   62,    54,   46,    38,    30,   22,
              14,    6,    61,   53,    45,    37,   29,
              21,   13,     5,   28,    20,    12,    4
               ]

        tempPCList = []
        s = ""
        i = 0

        while(i <= len(PC1) - 1):
            tempPCList.append(binKey[PC1[i] - 1])
            i += 1

        print("The key after the PC-1 \n")
        pc1K = s.join(tempPCList)
        print(pc1K,"\n")

        #================================================================================

        #====================== Shift the key in 16 rounds ==============================


        Kl0 = pc1K[:28]
        Kr0 = pc1K[-28:]


        kl1 = Kl0[1:28] + Kl0[0]
        kr1 = Kr0[1:28] + Kr0[0]


        kl2 = kl1[1:28] + kl1[0]
        kr2 = kr1[1:28] + kr1[0]

        kl3 = kl2[2:28] + kl2[0] + kl2[1]
        kr3 = kr2[2:28] + kr2[0] + kr2[1]

        kl4 = kl3[2:28] + kl3[0] + kl3[1]
        kr4 = kr3[2:28] + kr3[0] + kr3[1]

        kl5 = kl4[2:28] + kl4[0] + kl4[1]
        kr5 = kr4[2:28] + kr4[0] + kr4[1]

        kl6 = kl5[2:28] + kl5[0] + kl5[1]
        kr6 = kr5[2:28] + kr5[0] + kr5[1]

        kl7 = kl6[2:28] + kl6[0] + kl6[1]
        kr7 = kr6[2:28] + kr6[0] + kr6[1]

        kl8 = kl7[2:28] + kl7[0] + kl7[1]
        kr8 = kr7[2:28] + kr7[0] + kr7[1]

        kl9 = kl8[1:28] + kl8[0]
        kr9 = kr8[1:28] + kr8[0]

        kl10 = kl9[2:28] + kl9[0] + kl9[1]
        kr10 = kr9[2:28] + kr9[0] + kr9[1]

        kl11 = kl10[2:28] + kl10[0] + kl10[1]
        kr11 = kr10[2:28] + kr10[0] + kr10[1]

        kl12 = kl11[2:28] + kl11[0] + kl11[1]
        kr12 = kr11[2:28] + kr11[0] + kr11[1]

        kl13 = kl12[2:28] + kl12[0] + kl12[1]
        kr13 = kr12[2:28] + kr12[0] + kr12[1]

        kl14 = kl13[2:28] + kl13[0] + kl13[1]
        kr14 = kr13[2:28] + kr13[0] + kr13[1]

        kl15 = kl14[2:28] + kl14[0] + kl14[1]
        kr15 = kr14[2:28] + kr14[0] + kr14[1]

        kl16 = kl15[1:28] + kl15[0]
        kr16 = kr15[1:28] + kr15[0]



        Key1  = kl1 + kr1; Key2  = kl2 + kr2; Key3  = kl3 + kr3; Key4  = kl4 + kr4
        Key5  = kl5 + kr5; Key6  = kl6 + kr6; Key7  = kl7 + kr7; Key8  = kl8 + kr8
        Key9  = kl9 + kr9; Key10 = kl10 + kr10; Key11 = kl11 + kr11; Key12 = kl12 + kr12
        Key13 = kl13 + kr13; Key14 = kl14 + kr14; Key15 = kl15 + kr15; Key16 = kl16 + kr16

        #================================================================================


        #========================== Enter the 16 sub keys on PC-2 =======================

        PC2 = [
            14,    17,   11,    24,     1,    5,
            3,     28,   15,     6,    21,   10,
            23,    19,   12,     4,    26,    8,
            16,     7,   27,    20,    13,    2,
            41,    52,   31,    37,    47,   55,
            30,    40,   51,    45,    33,   48,
            44,    49,   39,    56,    34,   53,
            46,    42,   50,    36,    29,   32
        ]

        tempPCList1  = []; tempPCList2  = []; tempPCList3  = []; tempPCList4  = [];
        tempPCList5  = []; tempPCList6  = []; tempPCList7  = []; tempPCList8  = [];
        tempPCList9  = []; tempPCList10 = []; tempPCList11 = []; tempPCList12 = [];
        tempPCList13 = []; tempPCList14 = []; tempPCList15 = []; tempPCList16 = [];


        s = ""
        i = 0

        while (i <= len(PC2) - 1):

            tempPCList1.append(Key1[PC2[i] - 1]); tempPCList2.append(Key2[PC2[i] - 1])
            tempPCList3.append(Key3[PC2[i] - 1]); tempPCList4.append(Key4[PC2[i] - 1])
            tempPCList5.append(Key5[PC2[i] - 1]); tempPCList6.append(Key6[PC2[i] - 1])
            tempPCList7.append(Key7[PC2[i] - 1]); tempPCList8.append(Key8[PC2[i] - 1])
            tempPCList9.append(Key9[PC2[i] - 1]); tempPCList10.append(Key10[PC2[i] - 1])
            tempPCList11.append(Key11[PC2[i] - 1]); tempPCList12.append(Key12[PC2[i] - 1])
            tempPCList13.append(Key13[PC2[i] - 1]); tempPCList14.append(Key14[PC2[i] - 1])
            tempPCList15.append(Key15[PC2[i] - 1]); tempPCList16.append(Key16[PC2[i] - 1])

            i += 1

        print("The 16 sub keys for the encryption operartion are: \n")

        K1 = s.join(tempPCList1); K2 = s.join(tempPCList2)
        K3 = s.join(tempPCList3); K4 = s.join(tempPCList4)
        K5 = s.join(tempPCList5); K6 = s.join(tempPCList6)
        K7 = s.join(tempPCList7); K8 = s.join(tempPCList8)
        K9 = s.join(tempPCList9); K10 = s.join(tempPCList10)
        K11 = s.join(tempPCList11); K12 = s.join(tempPCList12)
        K13 = s.join(tempPCList13); K14 = s.join(tempPCList14)
        K15 = s.join(tempPCList15); K16 = s.join(tempPCList16)
        
        List_of_Keys = [
                        K1, K2, K3, K4, K5, K6, K7, K8,
                        K9, K10, K11, K12, K13, K14, K15, K16 
        ]

        print("K1="," ",K1); print("K2="," ",K2); print("K3="," ",K3); print("K4="," ",K4)
        print("K5="," ",K5); print("K6="," ",K6); print("K7="," ",K7); print("K8="," ",K8)
        print("K9="," ",K9); print("K10="," ",K10); print("K11="," ",K11); print("K12="," ",K12)
        print("K13="," ",K13); print("K14="," ",K14); print("K15="," ",K15); print("K16="," ",K16)
        print("\n")
        #================================================================================

        # ============================ Message Processing ===============================

        initialMsg = plainText.get(1.0,END)
        print(len(initialMsg))

        if len(initialMsg) < 9 or len(initialMsg) > 9:
            print("Please, enter 64 bits or 8 bytes as initial message ")
        else:
            byteMsg = initialMsg.encode('utf-8')
            hexaMsg = str(byteMsg.hex())
            tempMsg = []
            s = ""
            for i in str(hexaMsg):
                for j in hexa_to_bin:
                    if i == j:
                        tempMsg.append(hexa_to_bin[j])
            binMsg = s.join(tempMsg)

            # ==============================================================================

            #======================== Enter message on IP array ============================

            IP = [
                58,   50,   42,    34,    26,   18,    10,    2,
                60,   52,   44,    36,    28,   20,    12,    4,
                62,   54,   46,    38,    30,   22,    14,    6,
                64,   56,   48,    40,    32,   24,    16,    8,
                57,   49,   41,    33,    25,   17,     9,    1,
                59,   51,   43,    35,    27,   19,    11,    3,
                61,   53,   45,    37,    29,   21,    13,    5,
                63,   55,   47,    39,    31,   23,    15,    7
            ]

            tempIPList = []
            s = ""
            i = 0

            while (i <= len(IP) - 1):
                tempIPList.append(binMsg[IP[i] - 1])
                i += 1

            #print("The message after the IP \n")
            msgIP = s.join(tempIPList)
            #print(msgIP, "\n")

            #===============================================================================

            L0 = msgIP[:32]
            R0 = msgIP[-32:]
            
            LeftSideList = [L0]
            RightSideList = [R0]
            
            

            for i in range(16):
        
                    print("Encryption:"," ","Round", i+1)
                    LeftSideList.append(RightSideList[i])
                    E = [
                        32,    1,    2,     3,     4,    5,
                        4,     5,    6,     7,     8,    9,
                        8,     9,    10,    11,    12,   13,
                        12,    13,   14,    15,    16,   17,
                        16,    17,   18,    19,    20,   21,
                        20,    21,   22,    23,    24,   25,
                        24,    25,   26,    27,    28,   29,
                        28,    29,   30,    31,    32,    1
                    ]

                    tempERList = []
                    s = ""
                    m = 0
                    R = RightSideList[i]

                    while (m <= len(E) - 1):
                        tempERList.append(R[E[m] - 1])
                        m += 1


                    ER = s.join(tempERList)

                    tempF = []
                    s = ""
                    SUB_KEY= List_of_Keys[i]
                    
                    for x in range(48):
                        if (SUB_KEY[x] == '0' and ER[x] == '0' or SUB_KEY[x] == '1' and ER[x] == '1'):
                            tempF.append('0')
                        elif (SUB_KEY[x] == '0' and ER[x] == '1' or SUB_KEY[x] == '1' and ER[x] == '0'):
                            tempF.append('1')

                    xorV = s.join(tempF)

                    divideR = []; start = 0; inc = 5; end = 47
                    while(start <= end):
                        divideR.append(xorV[start:inc + 1])
                        start = inc + 1
                        inc += 6
                    
                    
                    tempSboxesList = []
                    for p in range(len(divideR)):
                        
                        item = divideR[p]
                        dict = Sboxes[p]
                        tempSboxesList.append(dict[item])
                    
                    
                    Results_of_Sboxes = s.join(tempSboxesList)
                    
                    P = [
                         
                         16,   7,  20,  21,
                         29,  12,  28,  17,
                          1,  15,  23,  26,
                          5,  18,  31,  10,
                          2,   8,  24,  14,
                         32,  27,   3,   9,
                         19,  13,  30,   6,
                         22,  11,   4,  25
                    ]
                    
                    counter = 0
                    s = ''
                    tempFList = []
                    while (counter <= len(P) - 1):
                        tempFList.append(Results_of_Sboxes[P[counter] - 1])
                        counter += 1
                    
                    F = s.join(tempFList)
                    #print("F =", " ",F)
                    
                    tempNewR = []
                    s = ''
                    PreviousL = LeftSideList[i]
                    for n in range(32):
                        if (F[n] == '0' and PreviousL[n] == '0' or F[n] == '1' and PreviousL[n] == '1'):
                            tempNewR.append('0')
                        elif (F[n] == '0' and PreviousL[n] == '1' or F[n] == '1' and PreviousL[n] == '0'):
                            tempNewR.append('1')

                    
                    NextR = s.join(tempNewR)
                    RightSideList.append(NextR)
                    print(NextR, "\n")
                    
                    #print("L =", " ",LeftSideList)
                    #print("R =", " ",RightSideList)
                    
                    #print(RightSideList[i + 1], " ", LeftSideList[i])
                    
                    if (i == 15):
                    
                        tempCipher = RightSideList[i + 1] + LeftSideList[i + 1]
                        
                        ipInverse = [
                                40,     8,   48,    16,    56,   24,    64,   32,
                                39,     7,   47,    15,    55,   23,    63,   31,
                                38,     6,   46,    14,    54,   22,    62,   30,
                                37,     5,   45,    13,    53,   21,    61,   29,
                                36,     4,   44,    12,    52,   20,    60,   28,
                                35,     3,   43,    11,    51,   19,    59,   27,
                                34,     2,   42,    10,    50,   18,    58,   26,
                                33,     1,   41,     9,    49,   17,    57,   25
                        ]
                        
                         
                        count = 0
                        s = ''
                        tempCipherList = []
                        while (count <= len(ipInverse) - 1):
                            tempCipherList.append(tempCipher[ipInverse[count] - 1])
                            count += 1
                        
                        Cipher = s.join(tempCipherList)
                        print("Cipher text ="," ",Cipher)
                        
                        divideCipher = []; start = 0; inc = 3; end = 63
                        while(start <= end):
                            divideCipher.append(Cipher[start:inc + 1])
                            start = inc + 1
                            inc += 4
                        
                        #print(divideCipher)
                        
                        Cipher_Hexa_List = []
                        s = ''
                        for c1 in divideCipher:
                            for d1 in hexa_to_bin:
                                if c1 == hexa_to_bin[d1]:
                                    Cipher_Hexa_List.append(d1)
                        #print(Cipher_Hexa)
                        
                        Cipher_Hexa = s.join(Cipher_Hexa_List)
                        cipherText.insert(INSERT,Cipher_Hexa)





def Decrypt():

    #====================== Key Processing ===========================================

    initialKey = mainKey.get().lower()

    if len(initialKey) < 16 or len(initialKey) > 16:
        print("Please, enter 64 bits or 8 bytes as initial key ")
    else:
        byteKey = initialKey.encode('utf-8')
        hexaKey   = str(initialKey)
        tempKey   = []
        s         = ""
        for i in str(hexaKey):
            for j in hexa_to_bin:
                if i == j:
                    tempKey.append(hexa_to_bin[j])
        binKey  = s.join(tempKey)
       

        #==============================================================================


        #========== process key bits on a permutation array of 56 values ================

        PC1 = [
              57,   49,    41,   33,    25,    17,    9,
               1,   58,    50,   42,    34,    26,   18,
              10,    2,    59,   51,    43,    35,   27,
              19,   11,     3,   60,    52,    44,   36,
              63,   55,    47,   39,    31,    23,   15,
               7,   62,    54,   46,    38,    30,   22,
              14,    6,    61,   53,    45,    37,   29,
              21,   13,     5,   28,    20,    12,    4
               ]

        tempPCList = []
        s = ""
        i = 0

        while(i <= len(PC1) - 1):
            tempPCList.append(binKey[PC1[i] - 1])
            i += 1

        print("The key after the PC-1 \n")
        pc1K = s.join(tempPCList)
        print(pc1K,"\n")

        #================================================================================

        #====================== Shift the key in 16 rounds ==============================


        Kl0 = pc1K[:28]
        Kr0 = pc1K[-28:]


        kl1 = Kl0[1:28] + Kl0[0]
        kr1 = Kr0[1:28] + Kr0[0]


        kl2 = kl1[1:28] + kl1[0]
        kr2 = kr1[1:28] + kr1[0]

        kl3 = kl2[2:28] + kl2[0] + kl2[1]
        kr3 = kr2[2:28] + kr2[0] + kr2[1]

        kl4 = kl3[2:28] + kl3[0] + kl3[1]
        kr4 = kr3[2:28] + kr3[0] + kr3[1]

        kl5 = kl4[2:28] + kl4[0] + kl4[1]
        kr5 = kr4[2:28] + kr4[0] + kr4[1]

        kl6 = kl5[2:28] + kl5[0] + kl5[1]
        kr6 = kr5[2:28] + kr5[0] + kr5[1]

        kl7 = kl6[2:28] + kl6[0] + kl6[1]
        kr7 = kr6[2:28] + kr6[0] + kr6[1]

        kl8 = kl7[2:28] + kl7[0] + kl7[1]
        kr8 = kr7[2:28] + kr7[0] + kr7[1]

        kl9 = kl8[1:28] + kl8[0]
        kr9 = kr8[1:28] + kr8[0]

        kl10 = kl9[2:28] + kl9[0] + kl9[1]
        kr10 = kr9[2:28] + kr9[0] + kr9[1]

        kl11 = kl10[2:28] + kl10[0] + kl10[1]
        kr11 = kr10[2:28] + kr10[0] + kr10[1]

        kl12 = kl11[2:28] + kl11[0] + kl11[1]
        kr12 = kr11[2:28] + kr11[0] + kr11[1]

        kl13 = kl12[2:28] + kl12[0] + kl12[1]
        kr13 = kr12[2:28] + kr12[0] + kr12[1]

        kl14 = kl13[2:28] + kl13[0] + kl13[1]
        kr14 = kr13[2:28] + kr13[0] + kr13[1]

        kl15 = kl14[2:28] + kl14[0] + kl14[1]
        kr15 = kr14[2:28] + kr14[0] + kr14[1]

        kl16 = kl15[1:28] + kl15[0]
        kr16 = kr15[1:28] + kr15[0]



        Key1  = kl1 + kr1; Key2  = kl2 + kr2; Key3  = kl3 + kr3; Key4  = kl4 + kr4
        Key5  = kl5 + kr5; Key6  = kl6 + kr6; Key7  = kl7 + kr7; Key8  = kl8 + kr8
        Key9  = kl9 + kr9; Key10 = kl10 + kr10; Key11 = kl11 + kr11; Key12 = kl12 + kr12
        Key13 = kl13 + kr13; Key14 = kl14 + kr14; Key15 = kl15 + kr15; Key16 = kl16 + kr16

        #================================================================================


        #========================== Enter the 16 sub keys on PC-2 =======================

        PC2 = [
            14,    17,   11,    24,     1,    5,
            3,     28,   15,     6,    21,   10,
            23,    19,   12,     4,    26,    8,
            16,     7,   27,    20,    13,    2,
            41,    52,   31,    37,    47,   55,
            30,    40,   51,    45,    33,   48,
            44,    49,   39,    56,    34,   53,
            46,    42,   50,    36,    29,   32
        ]

        tempPCList1  = []; tempPCList2  = []; tempPCList3  = []; tempPCList4  = [];
        tempPCList5  = []; tempPCList6  = []; tempPCList7  = []; tempPCList8  = [];
        tempPCList9  = []; tempPCList10 = []; tempPCList11 = []; tempPCList12 = [];
        tempPCList13 = []; tempPCList14 = []; tempPCList15 = []; tempPCList16 = [];


        s = ""
        i = 0

        while (i <= len(PC2) - 1):

            tempPCList1.append(Key1[PC2[i] - 1]); tempPCList2.append(Key2[PC2[i] - 1])
            tempPCList3.append(Key3[PC2[i] - 1]); tempPCList4.append(Key4[PC2[i] - 1])
            tempPCList5.append(Key5[PC2[i] - 1]); tempPCList6.append(Key6[PC2[i] - 1])
            tempPCList7.append(Key7[PC2[i] - 1]); tempPCList8.append(Key8[PC2[i] - 1])
            tempPCList9.append(Key9[PC2[i] - 1]); tempPCList10.append(Key10[PC2[i] - 1])
            tempPCList11.append(Key11[PC2[i] - 1]); tempPCList12.append(Key12[PC2[i] - 1])
            tempPCList13.append(Key13[PC2[i] - 1]); tempPCList14.append(Key14[PC2[i] - 1])
            tempPCList15.append(Key15[PC2[i] - 1]); tempPCList16.append(Key16[PC2[i] - 1])

            i += 1

        print("The 16 sub keys for the encryption operartion are: \n")

        K1 = s.join(tempPCList1); K2 = s.join(tempPCList2)
        K3 = s.join(tempPCList3); K4 = s.join(tempPCList4)
        K5 = s.join(tempPCList5); K6 = s.join(tempPCList6)
        K7 = s.join(tempPCList7); K8 = s.join(tempPCList8)
        K9 = s.join(tempPCList9); K10 = s.join(tempPCList10)
        K11 = s.join(tempPCList11); K12 = s.join(tempPCList12)
        K13 = s.join(tempPCList13); K14 = s.join(tempPCList14)
        K15 = s.join(tempPCList15); K16 = s.join(tempPCList16)
        
        List_of_Keys = [
                        K1, K2, K3, K4, K5, K6, K7, K8,
                        K9, K10, K11, K12, K13, K14, K15, K16 
        ]

        print("K1="," ",K1); print("K2="," ",K2); print("K3="," ",K3); print("K4="," ",K4)
        print("K5="," ",K5); print("K6="," ",K6); print("K7="," ",K7); print("K8="," ",K8)
        print("K9="," ",K9); print("K10="," ",K10); print("K11="," ",K11); print("K12="," ",K12)
        print("K13="," ",K13); print("K14="," ",K14); print("K15="," ",K15); print("K16="," ",K16)
        print("\n")
        #================================================================================

        # ============================ Message Processing ===============================

        

        cipherMsg = cipherText.get(1.0,END)

        if len(cipherMsg) < 17 or len(cipherMsg) > 17:
            print("Your cipher text is not matched the 64-bit length!")
        else:
            tempMsg = []
            s = ""
            for i in str(cipherMsg):
                for j in hexa_to_bin:
                    if i == j:
                        tempMsg.append(hexa_to_bin[j])
            binMsg = s.join(tempMsg)
            print(binMsg)

            # ==============================================================================

            #======================== Enter message on IP array ============================

            IP = [
                58,   50,   42,    34,    26,   18,    10,    2,
                60,   52,   44,    36,    28,   20,    12,    4,
                62,   54,   46,    38,    30,   22,    14,    6,
                64,   56,   48,    40,    32,   24,    16,    8,
                57,   49,   41,    33,    25,   17,     9,    1,
                59,   51,   43,    35,    27,   19,    11,    3,
                61,   53,   45,    37,    29,   21,    13,    5,
                63,   55,   47,    39,    31,   23,    15,    7
            ]

            tempIPList = []
            s = ""
            i = 0

            while (i <= len(IP) - 1):
                tempIPList.append(binMsg[IP[i] - 1])
                i += 1

            #print("The message after the IP \n")
            msgIP = s.join(tempIPList)
            #print(msgIP, "\n")

            #===============================================================================
            
            R16 = msgIP[:32]
            L16 = msgIP[-32:]
            
            LeftSideList = [R16]
            RightSideList = [L16]
            
            

            for i in range(16):
        
                    print("Decryption:"," ","Round", i + 1)
                    LeftSideList.append(RightSideList[i])
                    E = [
                        32,    1,    2,     3,     4,    5,
                        4,     5,    6,     7,     8,    9,
                        8,     9,    10,    11,    12,   13,
                        12,    13,   14,    15,    16,   17,
                        16,    17,   18,    19,    20,   21,
                        20,    21,   22,    23,    24,   25,
                        24,    25,   26,    27,    28,   29,
                        28,    29,   30,    31,    32,    1
                    ]

                    tempERList = []
                    s = ""
                    m = 0
                    R = RightSideList[i]

                    while (m <= len(E) - 1):
                        tempERList.append(R[E[m] - 1])
                        m += 1


                    ER = s.join(tempERList)

                    tempF = []
                    s = ""
                    SUB_KEY= List_of_Keys[15 - i]
                    
                    for x in range(48):
                        if (SUB_KEY[x] == '0' and ER[x] == '0' or SUB_KEY[x] == '1' and ER[x] == '1'):
                            tempF.append('0')
                        elif (SUB_KEY[x] == '0' and ER[x] == '1' or SUB_KEY[x] == '1' and ER[x] == '0'):
                            tempF.append('1')

                    xorV = s.join(tempF)

                    divideR = []; start = 0; inc = 5; end = 47
                    while(start <= end):
                        divideR.append(xorV[start:inc + 1])
                        start = inc + 1
                        inc += 6
                    
                    
                    tempSboxesList = []
                    for p in range(len(divideR)):
                        
                        item = divideR[p]
                        dict = Sboxes[p]
                        tempSboxesList.append(dict[item])
                    
                    
                    Results_of_Sboxes = s.join(tempSboxesList)
                    
                    P = [
                         
                         16,   7,  20,  21,
                         29,  12,  28,  17,
                          1,  15,  23,  26,
                          5,  18,  31,  10,
                          2,   8,  24,  14,
                         32,  27,   3,   9,
                         19,  13,  30,   6,
                         22,  11,   4,  25
                    ]
                    
                    counter = 0
                    s = ''
                    tempFList = []
                    while (counter <= len(P) - 1):
                        tempFList.append(Results_of_Sboxes[P[counter] - 1])
                        counter += 1
                    
                    F = s.join(tempFList)
                    #print("F =", " ",F)
                    
                    tempNewR = []
                    s = ''
                    PreviousR = LeftSideList[i]
                    for n in range(32):
                        if (F[n] == '0' and PreviousR[n] == '0' or F[n] == '1' and PreviousR[n] == '1'):
                            tempNewR.append('0')
                        elif (F[n] == '0' and PreviousR[n] == '1' or F[n] == '1' and PreviousR[n] == '0'):
                            tempNewR.append('1')

                    
                    NextL = s.join(tempNewR)
                    RightSideList.append(NextL)
                    print(NextL, "\n")
                    
                    #print("L =", " ",LeftSideList)
                    #print("R =", " ",RightSideList)
                    
                    #print(RightSideList[i + 1], " ", LeftSideList[i])
                    
                    if (i == 15):
                    
                        tempPlain = RightSideList[i + 1] + LeftSideList[i + 1]
                        
                        ipInverse = [
                                40,     8,   48,    16,    56,   24,    64,   32,
                                39,     7,   47,    15,    55,   23,    63,   31,
                                38,     6,   46,    14,    54,   22,    62,   30,
                                37,     5,   45,    13,    53,   21,    61,   29,
                                36,     4,   44,    12,    52,   20,    60,   28,
                                35,     3,   43,    11,    51,   19,    59,   27,
                                34,     2,   42,    10,    50,   18,    58,   26,
                                33,     1,   41,     9,    49,   17,    57,   25
                        ]
                        
                         
                        count = 0
                        s = ''
                        tempPlainList = []
                        while (count <= len(ipInverse) - 1):
                            tempPlainList.append(tempPlain[ipInverse[count] - 1])
                            count += 1
                        
                        plain = s.join(tempPlainList)
                        print("Plain text ="," ",plain)
                    
                        dividePlaintxt = []; start = 0; inc = 3; end = 63
                        while(start <= end):
                            dividePlaintxt.append(plain[start:inc + 1])
                            start = inc + 1
                            inc += 4
                        
                        #print(divideCipher)
                        
                        Plain_Hexa_List = []
                        s = ''
                        for c1 in dividePlaintxt:
                            for d1 in hexa_to_bin:
                                if c1 == hexa_to_bin[d1]:
                                    Plain_Hexa_List.append(d1)
                        #print(Cipher_Hexa)
                        
                        Plain_Hexa = s.join(Plain_Hexa_List)
                        
                        dividePlainHexa = []; start = 0; inc = 1; end = 15
                        while(start <= end):
                            dividePlainHexa.append(Plain_Hexa[start:inc + 1])
                            start = inc + 1
                            inc += 2
                        
                        Plain_Char_List = []
                        s = ''
                        for h1 in dividePlainHexa:
                            for c1 in hexa_to_char:
                                if h1 == c1:
                                    Plain_Char_List.append(hexa_to_char[c1])
                        
                        
                        finalPlain_Text = s.join(Plain_Char_List)
                        plainText.insert(INSERT, finalPlain_Text)








#================================= CREATE THE NECESSARY WIDGETS HERE ==============================

Label1 = Label(tab_des, text="Key", font="Calibri", bg="lightblue").place(x=60, y=60)
ED_Key = Entry(tab_des, textvariable=mainKey, font="Calibri", width="50").place(x=60, y=100)


Label2 = Label(tab_des, text="The Plain Text", font="Calibri", bg="lightblue").place(x=140, y=160)
clearBtn1 = Button(tab_des, text="Clear", width="8", font="Calibri", command=clear1).place(x=180, y=310)


Label3 = Label(tab_des, text="The Cipher Text", font="Calibri", bg="lightblue").place(x=560, y=160)
clearBtn2 = Button(tab_des, text="Clear", width="8", font="Calibri", command=clear2).place(x=670, y=310)


encBtn = Button(tab_des, text="Encrypt", width="8", font="Calibri", command=Encrypt).place(x=435, y=205)
decBtn = Button(tab_des, text="Decrypt", width="8", font="Calibri", command=Decrypt).place(x=435, y=250)


plainText = ScrolledText(tab_des, height=5, width=40)
cipherText = ScrolledText(tab_des, height=5, width=40)
plainText.grid(row=1, column=1)
cipherText.grid(row=1, column=1)
plainText.place(x=60, y=200)
cipherText.place(x=540, y=200)


# ====================== AES ==================
def aes_print(msg, **kwargs):
    print(f'[AES] {msg}', **kwargs)

aes : AES = None
def aes_on_encrypt_click():
    aes_print('encrypting')
    key = aes_mainKey.get().upper().strip()
    if len(key) != 32:
        aes_print(f'Please enter key of size 128-bit as hexadecimal, got {len(key)}')
        return
    aes_print(f'Key is {key}, {len(key)}')
    text = aes_plainText.get(1.0, END).strip()

    global aes 
    print(len(text))
    to_pad = 0
    if len(text) % 16 != 0:
        filled = len(text) % 16
        to_pad = 16 - filled
        aes_print(f'Padding last block with {to_pad} bytes')
    text += 'z'*to_pad
    print(text)
    blocks = list()
    aes_cipherText.delete(1.0, END)

    for i in range(0, len(text), 16):
        blocks.append(text[i:i+16])
        aes = AES(key, text[i:i+16].encode('ascii'))
        print(f'plaintext is {text} or {aes.get_state_as_hex_string()}')
        aes.Encrypt()
        aes_cipherText.insert(1.0, aes.get_state_as_hex_string())

    fill_table()
    
def aes_on_decrypt_click():
    cipher = aes_cipherText.get(1.0, END).lower().strip()
    print(len(cipher))
    cipher_bytes = bytes.fromhex(cipher)
    print(cipher_bytes)
    print(len(cipher_bytes))
    key = aes_mainKey.get().lower().strip()
    if len(key) != 32:
        print(f'Please enter key of size 128-bit as hexadecimal, got {len(key)}')
    print(f'Key is {key}, {len(key)}')
    if len(cipher) != 32:
        print(f'Please enter ciphertext of size 128-bit or 32 hex char, got {len(cipher)} hex chars')
    global aes
    aes_plainText.delete(1.0, END)
    for i in range(0, len(cipher_bytes), 16):
        #blocks.append(cipher_bytes[i:i+16])
        aes = AES(key, cipher_bytes[i:i+16])
        #print(f'plaintext is {text} or {aes.get_state_as_hex_string()}')
        aes.Decrypt()
        aes_plainText.insert(1.0, bytes.fromhex(aes.get_state_as_hex_string()))
    # aes = AES(key, cipher_bytes) # We don't know if the key is the one used for enc. So make new instance.
    # aes.Decrypt()
    # print(len(bytes.fromhex(aes.get_state_as_hex_string())))
    # aes_plainText.insert(1.0, str(bytes.fromhex(aes.get_state_as_hex_string())))


def aes_on_clear_text_click():
    aes_plainText.delete(1.0, END)

def aes_on_clear_cipher_click():
    aes_cipherText.delete(1.0, END)

def clear_table(table: ttk.Treeview):
    for entry in table.get_children():
        aes_table.delete(entry)

def fill_table():
    clear_table(aes_table)

    global aes

    i = 0
    for round_  in aes.rounds_enc:
        round_ : AESRound
        in_state = aes.convert_block_to_hex_string(round_.in_block).upper()
        out_state = aes.convert_block_to_hex_string(round_.add_round_key_state).upper()
        aes_print(round_.key_words)
        k = aes.convert_block_to_hex_string(round_.key_words).upper()
        aes_table.insert(parent='', index=END, values=(i, in_state, out_state, k))
        i += 1

def aes_gen_random_key():
    pass  
   
        
aes_mainKey = StringVar()
aes_mainKey.set('EE495EE495EE495EEE495EE495EE494E')

aes_plainText = ScrolledText(tab_aes, height=5, width=40)
aes_cipherText = ScrolledText(tab_aes, height=5, width=40)
aes_plainText.grid(row=1, column=1)
aes_cipherText.grid(row=1, column=1)
aes_plainText.place(x=60, y=200)
aes_cipherText.place(x=540, y=200)
aes_plainText.insert(1.0, 'heshamheshamhesh')

aes_Label1 = Label(tab_aes, text="Key",font="Calibri",
                   bg="lightblue").place(x=60, y=60)
aes_ED_Key = Entry(tab_aes, textvariable=aes_mainKey, font="Calibri",
                   width="50").place(x=60, y=100)


aes_Label2 = Label(tab_aes, text="The Plain Text", font="Calibri",
                   bg="lightblue").place(x=140, y=160)
aes_clearBtn1 = Button(tab_aes, text="Clear", width="8",
                       font="Calibri", command=aes_on_clear_text_click).place(x=180, y=310)


aes_Label3 = Label(tab_aes, text="The Cipher Text", font="Calibri",
                   bg="lightblue").place(x=560, y=160)
aes_clearBtn2 = Button(tab_aes, text="Clear", width="8", font="Calibri",
                       command=aes_on_clear_cipher_click).place(x=670, y=310)

aes_encBtn = Button(tab_aes, text="Encrypt", width="8", font="Calibri",
                    command=aes_on_encrypt_click).place(x=435, y=205)
aes_decBtn = Button(tab_aes, text="Decrypt", width="8", font="Calibri",
                    command=aes_on_decrypt_click).place(x=435, y=250)


style = ttk.Style()
style.configure('TreeView.Text', font='TkFixedFont')

aes_table = ttk.Treeview(tab_aes)
aes_table.place(x=350, y=350)
aes_table['columns'] = ('Round','In-state', 'Out-state', 'Key')
aes_table.column('#0', width=0, stretch=NO)
aes_table.column("Round", anchor=CENTER, width=50)
aes_table.column("In-state", anchor=CENTER, width=300)
aes_table.column("Out-state", anchor=CENTER, width=300)
aes_table.column("Key", anchor=CENTER, width=300)

aes_table.heading("#0",text="",anchor=CENTER)
aes_table.heading("Round",text="Round",anchor=CENTER)
aes_table.heading("In-state",text="In-state",anchor=CENTER)
aes_table.heading("Out-state",text="Out-state",anchor=CENTER)
aes_table.heading("Key",text="Key",anchor=CENTER)


# ====================== RSA ==================

rsa_key = None
N=0
E=1
D=2
P=3
Q=4
PHI=5
ID=6
def rsa_key_gen():
    global rsa_key
    size = int(rsa_keysize.get(), 10)
    rsa_print(f'Key size: {size}')
    rsa_key = rsa.generateKeys('gui', size)
    rsa_print(f'n: {rsa_key[N]}\n d: {rsa_key[D]}')
    rsa_pubkey_e.set(rsa_key[E])
    rsa_pubkey_n.set(rsa_key[N])
    rsa_privkey_d.set(rsa_key[D])
    rsa_p.set(rsa_key[P])
    rsa_q.set(rsa_key[Q])

def rsa_on_encrypt_click():
    global rsa_key
    msg = rsa_plainText.get(1.0, END)
    msg_list = msg.split()
    key_public = (rsa_key[N], rsa_key[E])
    cipher = ""
    for word in msg_list:
        cipher = cipher + " " + str(rsa.encrypt(word, key_public))
    #cipher = rsa.encrypt(msg, rsa_key)
    rsa_cipherText.insert(1.0, cipher)
    
def rsa_on_decrypt_click():
    global rsa_key
    rsa_print('decrypting')
    cipher = rsa_cipherText.get(1.0, END)
    cipher_list = cipher.split()    
    plain_text = ""
    rsa_print(f'cipher list: {cipher_list}')
    for cipher_word in cipher_list:
        plain_text = plain_text + " " + str(rsa.decrypt(int(cipher_word, 10),rsa_key[D],rsa_key[N]))
    rsa_plainText.delete(1.0, END)
    rsa_plainText.insert(1.0, plain_text)
    rsa_print(f'Message: {plain_text}')

def rsa_on_factorize_click():
    n = rsa_pubkey_n.get()
    factors = rsa.prime_factors(n, 10)
    rsa_cipherText.delete(1.0, END)
    rsa_cipherText.insert(1.0, str(factors))

def rsa_print(msg, **kwargs):
    print(f'[RSA] {msg}', **kwargs)

rsa_pubkey_e = StringVar()
rsa_pubkey_n = StringVar()
rsa_privkey_d = StringVar()
rsa_keysize = StringVar()
rsa_p = StringVar()
rsa_q = StringVar()

rsa_pubkey_e.set(65537)
rsa_keysize.set(1024)
rsa_e_field_label = Label(tab_rsa, text="Public e",font="Calibri",
                   bg="lightblue").place(x=60, y=70)
rsa_e_field = Entry(tab_rsa, textvariable=rsa_pubkey_e, font="Calibri",
                   width="50").place(x=60, y=100)
rsa_n_field_label = Label(tab_rsa, text="Public n",font="Calibri",
                   bg="lightblue").place(x=300, y=70)
rsa_n_field = Entry(tab_rsa, textvariable=rsa_pubkey_n, font="Calibri",
                   width="50").place(x=300, y=100)
rsa_n_field_label = Label(tab_rsa, text="Private d",font="Calibri",
                   bg="lightblue").place(x=700, y=70)
rsa_d_field = Entry(tab_rsa, textvariable=rsa_privkey_d, font="Calibri",
                   width="50").place(x=700, y=100)
rsa_p_field = Entry(tab_rsa, textvariable=rsa_p, font="Calibri",
                   width="50").place(x=700, y=120)
rsa_q_field = Entry(tab_rsa, textvariable=rsa_q, font="Calibri",
                   width="50").place(x=700, y=140)
rsa_genBtn = Button(tab_rsa, text="Generate Key", width="8", font="Calibri",
                    command=rsa_key_gen).place(x=50, y=150)
rsa_keysize_label = Label(tab_rsa, text="Key size",font="Calibri",
                   bg="lightblue").place(x=150, y=130)
rsa_keyszie_field = Entry(tab_rsa, textvariable=rsa_keysize, font="Calibri",
                   width="50").place(x=150, y=150)
rsa_encryptBtn = Button(tab_rsa, text="Encrypt", width="8", font="Calibri",
                    command=rsa_on_encrypt_click).place(x=50, y=550)
rsa_factorizeBtn = Button(tab_rsa, text="Prime factors", width="8", font="Calibri",
                    command=rsa_on_factorize_click).place(x=50, y=600)
rsa_decryptBtn = Button(tab_rsa, text="Decrypt", width="8", font="Calibri",
                    command=rsa_on_decrypt_click).place(x=620, y=550)
rsa_plainText = ScrolledText(tab_rsa, height=20, width=70)
rsa_cipherText = ScrolledText(tab_rsa, height=20, width=70)
rsa_plainText.grid(row=1, column=1)
rsa_cipherText.grid(row=1, column=1)
rsa_plainText.place(x=60, y=200)
rsa_cipherText.place(x=600, y=200)
rsa_plainText.insert(1.0, 'This is a test meessage from EE494/EE495 about RSA')
T.mainloop()

#===================================================================================================

