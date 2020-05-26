from charm.toolbox.pairinggroup import PairingGroup, GT
from PCHBA import PCHBA
import time


def main():
    d = 10
    trial = 100
    Test_Setup = False
    Test_KeyGen = False
    Test_Hash = False
    Test_Adapt = True
    Test_Verify = False
    Test_Judge = False

    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
    
    # AC17 CP-ABE under DLIN (2-linear)
    pchba = PCHBA(pairing_group, 2, 10)	# k = 10 (depth of the tree)

    # run the set up
    (sk, pk, msk, mpk) = pchba.setup()

    if Test_Setup:
        k = 10
        f = open('result_setup.txt', 'w+')
        f.write("("+str(k)+",")
        T=0
        Temp=0
        start = 0
        end = 0
        for i in range(trial):
            start = time.time()
            (sk, pk, msk, mpk) = pchba.setup()
            end = time.time()
            Temp=end - start
            T+=Temp
        T=T/trial
        f.write(str(T) + ")\n")
        f.close()

    # generate a key
    attr_list = ['ONE', 'TWO', 'THREE']
    sk_delta = pchba.keygen(sk, pk, msk, mpk, attr_list)

    if Test_KeyGen:
        d=10      # number of attributes
        NN = 100
        
        f = open('result_keygen.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(d):
                attr_list.append(str(i))
            for i in range(trial):
                start = time.time()
                sk_delta = pchba.keygen(sk, pk, msk, mpk, attr_list)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

   
    # generate a ciphertext
    policy_str = '((ONE and THREE) and (TWO OR FOUR))'

    m = None
    (m, p, h_prime, b, C, c, epk, sigma) = pchba.hash(m, policy_str)

    if Test_Hash:
        d=10      # number of attributes
        NN = 100
        print ("Hash Bench")
        f = open('result_hash.txt', 'w+')
        while d <= NN:
            # print ("No. Attr:" + str(d))
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            sk_delta = pchba.keygen(sk, pk, msk, mpk, attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            for i in range(trial):
                m = None
                start = time.time()
                (m, p, h_prime, b, C, c, epk, sigma) = pchba.hash(m, policy_str)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    
    if (pchba.verify(m, p, h_prime, b, C, c, epk, sigma) == 0):
        print ("Successful verification.")
    else:
        print ("Verification failed.")

    if Test_Verify:
        d=10      # number of attributes
        NN = 100
        print ("Verify Bench")
        f = open('result_verify.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            sk_delta = pchba.keygen(sk, pk, msk, mpk, attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            (m, p, h_prime, b, C, c, epk, sigma) = pchba.hash(m, policy_str)
            
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                pchba.verify(m, p, h_prime, b, C, c, epk, sigma)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()

    
    m_prime = None 
    ID_i = None

    (m_prime, p_prime, h_prime, b, C_prime, c_prime, epk_prime, sigma_prime) = pchba.adapt(sk_delta, m, m_prime, p, h_prime, b, C, c, epk, sigma, ID_i, policy_str)

    if Test_Adapt:
        d=10      # number of attributes
        NN = 100
        print ("Adapt Bench")
        f = open('result_adapt.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            sk_delta = pchba.keygen(sk, pk, msk, mpk, attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            (m, p, h_prime, b, C, c, epk, sigma) = pchba.hash(m, policy_str)
            
            for i in range(trial):
                m_prime = None 
                ID_i = None
                start = time.time()
                (m_prime, p_prime, h_prime, b, C_prime, c_prime, epk_prime, sigma_prime) = pchba.adapt(sk_delta, m, m_prime, p, h_prime, b, C, c, epk, sigma, ID_i, policy_str)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
    
    if (pchba.verify(m_prime, p_prime, h_prime, b, C_prime, c_prime, epk_prime, sigma_prime) == 0):
        print ("Successful verification.")
    else:
        print ("Verification failed.")

    if (pchba.judge(m, p, h_prime, b, C, c, epk, sigma, m_prime, p_prime, C_prime, c_prime, epk_prime, sigma_prime) == 0):
        print ("Successful verification.")
    else:
        print ("Verification failed.")
    
    if Test_Judge:
        d=10      # number of attributes
        NN = 100
        print ("Judge Bench")
        f = open('result_judge.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(i))
            sk_delta = pchba.keygen(sk, pk, msk, mpk, attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+str(2*j) + " and "+ str(2*j+1)+" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(2 * j) + " and " + str(2 * j + 1) + " )"
            
            (m, p, h_prime, b, C, c, epk, sigma) = pchba.hash(m, policy_str)
            m_prime = None 
            ID_i = None
            (m_prime, p_prime, h_prime, b, C_prime, c_prime, epk_prime, sigma_prime) = pchba.adapt(sk_delta, m, m_prime, p, h_prime, b, C, c, epk, sigma, ID_i, policy_str)
            
            for i in range(trial):
                start = time.time()
                pchba.judge(m, p, h_prime, b, C, c, epk, sigma, m_prime, p_prime, C_prime, c_prime, epk_prime, sigma_prime)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()


if __name__ == "__main__":
    debug = True
    main()
