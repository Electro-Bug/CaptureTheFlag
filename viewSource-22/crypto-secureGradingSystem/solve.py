from pwn import *
from pwnlib.util.iters import *
import string
import hashlib
from base64 import b64decode
from Crypto.Util.number import *
import ecdsa
from sympy.ntheory.modular import *
import gmpy


host = "104.197.118.147"
port = 10140

ALLOWED_CHARS = string.ascii_letters + string.digits

io = connect(host,port)

# pow
def verify( prefix, nonce, answer) -> bool:
	h = hashlib.sha256((prefix + nonce).encode('utf-8')).hexdigest()
	return h == answer
        
        
print(io.recvuntil(b"sha256(???? + "))
y,t = io.recvline().split(b"==")
y=y[:-2].decode()
t=t.strip().decode()
#print(t,verify("admi",y,t))
_pow = mbruteforce(lambda x : verify(x,y,t),ALLOWED_CHARS , length=4)
io.sendline(_pow.encode())

"""
Your answer: 
[+] Verification successful.

[+] Verifying with Professor...
Signature: (8482787452271401902922748160303764296768229955577079931985294193964499754222366005195233566195321811044617054291428, 1176911354260272275717643920377858641547071003053669546037690173465368419478493186270659058159862269705261703376161)
Signature: (8482787452271401902922748160303764296768229955577079931985294193964499754222366005195233566195321811044617054291428, 38956978466216913387009254610059733716843669274309309372252485183351586769010140394236782234220772283873625453976527)

[+] Verification successful.

[+] Distributing reports to tutors...
[-] Tutor 1:
N = 1662962804615265190470927985143455345979707058986691280004118982865987351810791031418892676493609416799767020487652384352291698110899254965631451553872203407587699705126481703342699957776440902837492477379140301071573679895121347151728850505935889400100022980467528523563815056710555038298558612671821241702374177674748791274405764974133322958612349881955837506180773574503430559601197256375124594221134388640454083835748179819231783041942933099193197414718742769997326042640248328494747788449244661929792260912019473169116746382597574776841250259936802551007755976940079295334925492352135711833
Ciphertext = GGQvzmvuS26OT2wxRpnmxQoWGQw0pcanMIJMrocv5Ib9WqIECRSQfDbKJCgQYDEwVPLo7qceyZ95MFUmKSRKgq1izsI4djpekZlulVHzl2lHt3Io/5pg4eAdGrV3SnLZ+x3GAXHlmvMcTRBFMiLfVgh+cL1xR6+lUxoKhfDVItojDFN/zJ3jCb02DtdL4lHRyf/+DtAbnoac/+v8DY5JYUIccOYydNYyQ0v8lKYoqas5TjTVAPZNF/L46+kr9goHhWov+S3xYGYIJ9/MJWrn3JJrdcQNJcjHiyy7/GqsuUmdBfD3iYCxLX/MA61yh5wLPOYIO+O68w==

[-] Tutor 2:
N = 963990415592853039291408346669649617791871549061481023485976464121761781058686285189592222801673155788376699590789616073426179704154155125378268083094388187205970409830362765993063293046212785287939884235237423415717084726048242803559409220753596560664969734590814487642457593088868385964789327061441251800195347189744885490607174037776448498318055959206517151704375788853150835237438753652069459458180330591505056109405577985425521480178199376392085089928086928457004739366467564444584066682680082608671616986286138709840005752603776158429563331553884226855429855291323546204778297376256346067
Ciphertext = DhK8jICm8sOcwyAbeAbbcVvZ7QmMd8zhNj7ez741oHFnP3JaWOmdzMMzrq9j5dTlUDyT3DQNRGRb3eFSovIcHMqaljjf9MfhN6umxaQVurCa2d0JcPXSCjtRyK/jp2fQWdG5mmA6u+7PVKcc9Wyt85yWhg/Ye+DIeT8E9NnD1lQZzLCJaE2hWb6fhLrRm0xE7IRCxupgmy6TPPafEAmTfMxRBu8HI+rjhFnHx6+TGWB9mfq7SPEVcdq5JGZUL2nGxcSkSABTFfadc4MOUKokIfj+aZjPIjUAOBadG27Xw+BAl5MaKkCBloQb1lg8Sroa/b9RHGKiDA==

[-] Tutor 3:
N = 668110968225200993962021841677399094607272411905137762637607768560572292061002056026479093039015637394567468096570699040108800393270033608195547072000355382701379572018119838130977824878771673758631653606388095392298119549701870425655788888998063954336862495254799151532852260398667071258984054027021640340237804034805830906468021670046478684728802354181922631337595111367558152246919873855804960687880267078408326642837212248845287886032964715795621775722661294904618239690757180606558137976222300846172508350317263983950554281110961534919671139875350086134206812072955272670833839333068085673
Ciphertext = BEIskAB6qvDnZTmynnwIne/2HTwPf4LD+THffXLr+Ci04bQRsjzBR2Yf3NEsEmxPKZ+dk/IWfEfIjqd+epJlMFRpAIPu2SqqB8w9DDglucdsMzdO3IsyqKG99A+Wd+UU4vQH6AqgvNsq0a7mjrkv0SYH0o9DTf+h6HRSzMT5TdnhtqpU7O9gdFtUt3tyQXW320ltx3fTN/RXR2nQuH8vNcaTPMKtw3lf/8gRTj7/naPWEb9jyLmbGbNuiBJOpoy6THwoU9DttT+oKW82W6EDa0HXyNPpEeXVn+oDNWH7Emc/KKlBooLH3G4izAaHcORv2lXSzneInQ==

[+] Distribution successful.

[+] I don't think you can forge it but hey, if you can really do so I will reward you the flag.
My secret key when communicating with professor: $
"""

io.recvuntil(b"Signature: (")
edcsa1 = io.recvline()


io.recvuntil(b"Signature: (")
edcsa2 = io.recvline()

print(edcsa1,edcsa2)

io.recvuntil(b"N = ")
N1 = int(io.recvline().strip())
io.recvuntil(b"Ciphertext = ")
c1 = bytes_to_long(b64decode( io.recvline().strip()))
print(N1,c1)

io.recvuntil(b"N = ")
N2 = int(io.recvline().strip())
io.recvuntil(b"Ciphertext = ")
c2 = bytes_to_long(b64decode( io.recvline().strip()))
print(N2,c2)

io.recvuntil(b"N = ")
N3 = int(io.recvline().strip())
io.recvuntil(b"Ciphertext = ")
c3 = bytes_to_long(b64decode( io.recvline().strip()))
print(N3,c3)

print("Solving CRT...")
a,n = solve_congruence((c1,N1), (c2,N2), (c3,N3),check=False)

# cublic root high precision
m0=gmpy.mpz(a)
report = long_to_bytes(m0.root(3)[0])
print(report)

# edcsa
curve=ecdsa.curves.NIST384p
G = curve.generator
n = G.order()

r1,s1 = edcsa1.split(b",")
r1 = int(r1)
s1 = int(s1[:-2])
r2,s2 = edcsa2.split(b",")
r2 = int(r2)
s2 = int(s2[:-2])
print(r1,r2,s1,s2)

STUDENT_NAME = "jayden_vs"
report_signed = STUDENT_NAME.encode('utf-8') + report
print(report_signed)

m1 = report_signed[:len(report_signed) // 2]
m2 = report_signed[len(report_signed) // 2:]

H1 = int(hashlib.sha256(m1).hexdigest(), 16)
H2 = int(hashlib.sha256(m2).hexdigest(), 16)

# R = k * self.G
# r = R.x() % self.n
# s = ((H + r * self.d) * pow(k, -1, self.n)) % self.n
print(s2,s1)
k = ((H2-H1)*pow(s2-s1,-1,n)) % n
print((k*G).x()%n,r1,r2)
assert (k*G).x() %n == r1
d = ((k*s1-H1)*pow(r1,-1,n)) %n


io.sendline(str(d))

io.interactive()


"""
[*] Switching to interactive mode

[+] Distribution successful.

[+] I don't think you can forge it but hey, if you can really do so I will reward you the flag.
My secret key when communicating with professor: [-] My system is broken :(
[-] Here is the flag: vsctf{Buff1ng_PuBL1c_k3y_CrYpT0(Gr4phy)_15_St1LL_1n53cur3}
"""
