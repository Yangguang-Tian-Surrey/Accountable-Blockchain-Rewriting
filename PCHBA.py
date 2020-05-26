from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
import hashlib

debug = False


class PCHBA(ABEnc):
    def __init__(self, group_obj, assump_size, k, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.assump_size = assump_size  # size of linear assumption, at least 2
        self.util = MSP(self.group, verbose)
        self.k = k
        self.index = k
        self.i = 5  
        self.j = 5  # we assume i = j, equals to identity-based encryption.
        self.msk = {}
        self.mpk = {}
        self.pk = None
        self.sk = None
        self.sk_delta = None
        self.ID_i = None
        self.ID_j = None
        self.I = []
        for i in range(self.k):
            self.I.append(self.group.random(ZR))


    def setup(self):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('\nSetup algorithm:\n')
	
	# (sk, pk)
        h = self.group.random(G2)
        self.sk = self.group.random(ZR)
        self.pk = h ** self.sk

	# (msk, mpk)
        g = self.group.random(G1)
        a0 = self.group.random(ZR)
        a1 = self.group.random(ZR)
        b0 = self.group.random(ZR)
        b1 = self.group.random(ZR)
        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        d0 = self.group.random(ZR)
        d1 = self.group.random(ZR)
        d2 = self.group.random(ZR)
        g_d1 = g ** d0
        g_d2 = g ** d1
        g_d3 = g ** d2
        Z = []	# {z1,...,zk}
        G = []  # {g1,...,gk}
        H = []  # {h1,...,hk}
        GZ = []	# {g_z1,...,g_zk}
        HZ = []	# {h_z1,...,h_zk}
        for i in range(self.k):
            Z.append(self.group.random(ZR))
            G.append(self.group.random(G1))
            H.append(self.group.random(G2))
            GZ.append(g ** Z[i])
            HZ.append(h ** Z[i])

        e_gh = pair(g, h)
        H1 = h ** a0
        H2 = h ** a1
        T1 = e_gh ** (d0*a0 + d2/alpha)
        T2 = e_gh ** (d1*a1 + d2/alpha)
        g_alpha = g ** alpha
        d = d0 + d1 + d2
        h_d_alpha = h ** (d/alpha)
        h_1_alpha = h ** (1/alpha)
        h_beta_alpha = h ** (beta/alpha)

        self.ID_i = 1
        for i in range(self.i):
            g_k = GZ[self.k-i-1]
            self.ID_i *= g_k ** self.I[i]
        self.ID_i *= g
        self.ID_j = 1
        for j in range(self.j):
            h_k = HZ[self.k-j-1]
            self.ID_j *= h_k ** self.I[j]
        self.ID_j *= h


        self.msk = {'a0':a0, 'a1':a1, 'b0':b0, 'b1':b1, 'alpha':alpha, 'beta':beta, 'd0':d0, 'd1':d1, 'd2':d2, 'g_d1':g_d1, 'g_d2':g_d2, 'g_d3':g_d3, 'Z':Z}
        self.mpk = {'g':g, 'h':h, 'H1':H1, 'H2':H2, 'T1':T1, 'T2':T2, 'GZ':GZ, 'HZ':HZ, 'g_alpha':g_alpha, 'h_d_alpha':h_d_alpha, 'h_1_alpha':h_1_alpha, 'h_beta_alpha':h_beta_alpha}
        
        return self.sk, self.pk, self.msk, self.mpk


    def keygen(self, sk, pk, msk, mpk, attr_list):
        """
        Generate a key for a list of attributes.
        """

        if debug:
            print('\nKey generation algorithm:\n')

        msk = self.msk
        mpk = self.mpk
        sk = self.sk
        pk = self.pk
        g = mpk['g']
        h = mpk['h']
        alpha = msk['alpha']
        x = sk
        d = msk['d0'] + msk['d1'] + msk['d2']
        R = self.group.random(ZR)
        r1 = self.group.random(ZR)
        r2 = self.group.random(ZR)
        r = r1 + r2
        h_b1_r1 = h ** (msk['b0']*r1)
        h_b2_r2 = h ** (msk['b1']*r2)
        h_r1_r2_alpha = h ** ((r1+r2)/alpha)
        g_1_alpha = g ** (1/alpha)
        g_r_alpha = g ** (r/alpha)
        g_R = g ** R
        sk0 = {'h_b1_r1':h_b1_r1, 'h_b2_r2':h_b2_r2, 'h_r1_r2_alpha':h_r1_r2_alpha, 'g_1_alpha':g_1_alpha, 'g_r_alpha':g_r_alpha, 'g_R':g_R}
        SK = {} # SK = {[sk_y_1, sk_y_2]} sk_y_t
        sk_prime = []
	
        for attr in attr_list:
            sigma_y = self.group.random(ZR)
            key = []
            for t in range(self.assump_size):
                input_for_hash1 = attr + str(0) + str(t)
                input_for_hash2 = attr + str(1) + str(t)
                input_for_hash3 = attr + str(2) + str(t)
                a_t = 'a' + str(t)
                sk_y_t = self.group.hash(input_for_hash1, G1) ** (msk['b0']*r1/msk[a_t])  * self.group.hash(input_for_hash2, G1) ** (msk['b1']*r2/msk[a_t]) * self.group.hash(input_for_hash3, G1) ** ((r1+r2)/(alpha*msk[a_t])) * g ** (sigma_y/(alpha*msk[a_t]))
                key.append(sk_y_t)
            key.append(g ** (-sigma_y))
            SK[attr] = key

        sigma_prime = self.group.random(ZR)
        for t in range(self.assump_size):
            input_for_hash1 = "010" + str(t)
            input_for_hash2 = "011" + str(t)
            input_for_hash3 = "012" + str(t)
            a_t = 'a' + str(t)
            d_t = 'd' + str(t)
            sk_t = g ** msk[d_t] * self.group.hash(input_for_hash1, G1) ** (msk['b0']*r1/msk[a_t])  * self.group.hash(input_for_hash2, G1) ** (msk['b1']*r2/msk[a_t]) * self.group.hash(input_for_hash3, G1) ** ((r1+r2)/(alpha*msk[a_t])) * g ** (sigma_prime/(alpha*msk[a_t]))
            sk_prime.append(sk_t)
        sk_prime.append(g ** msk['d2'] * g ** (-sigma_prime))	

        
        sk1 = g ** d * self.ID_i ** (alpha * r) * g ** (msk['beta']*R)

        sk2 = [None] * ((self.i-1)*2)
        for i in range(self.i-1):
            g_k = mpk['GZ'][self.i-1-i]
            sk2[i] = g_k ** (alpha*r)
            sk2[self.i+i-1] = g_k ** alpha
	
        ssk = {'sk0':sk0, 'sk_y_t':SK, 'sk_prime':sk_prime, 'sk1':sk1, 'sk2':sk2}
        self.sk_delta = {'x':x, 'ssk':ssk, 'attr_list':attr_list}

        return self.sk_delta
    
    def hash(self, m, policy_str):
        msk = self.msk
        mpk = self.mpk
        pk = self.pk
        h = mpk['h']
        g = mpk['g']
        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # step 1
        r = self.group.random(ZR)
        p = pk ** r
	
        # step 2
        R = self.group.random(ZR)
        sha256 = hashlib.new('sha256')
        sha256.update(self.group.serialize(R))
        hd = sha256.hexdigest() 
        seed = str(hd)
        e = self.group.hash(seed, ZR)
        h_prime = h ** e

        # step 3
        m = self.group.random(ZR)
        b = p * h_prime ** m
	
        # step 4
        s = []
        sum = 0	# sum = s1 + s2
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            s.append(rand)
            sum += rand
        _sk = sum
        _vk = self.ID_j ** (msk['alpha']*sum)

        # step 5
        ct0 = []
        H1 = mpk['H1']
        H2 = mpk['H2']
        ct0.append(H1**s[0])
        ct0.append(H2**s[1])
        ct0.append(h**(sum/msk['alpha']))
        ct0.append(mpk['h_beta_alpha'] ** sum)

        # pre-compute hashes
        hash_table = []
        for j in range(num_cols):
            x = []
            input_for_hash1 = '0' + str(j + 1)
            for l in range(self.assump_size + 1):
                y = []
                input_for_hash2 = input_for_hash1 + str(l)
                for t in range(self.assump_size):
                    input_for_hash3 = input_for_hash2 + str(t)
                    hashed_value = self.group.hash(input_for_hash3, G1)
                    y.append(hashed_value)
                x.append(y)
            hash_table.append(x)
	
        # compute C = ct_u_l
        C = {}
        for attr, row in mono_span_prog.items():
            ct = []
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
            for l in range(self.assump_size + 1):
                prod = 1
                cols = len(row)
                for t in range(self.assump_size):
                    input_for_hash = attr_stripped + str(l) + str(t)
                    prod1 = self.group.hash(input_for_hash, G1)
                    for j in range(cols):
                        prod1 *= (hash_table[j][l][t] ** row[j])
                    prod *= (prod1 ** s[t])
                ct.append(prod)
            C[attr] = ct
	

        sha256 = hashlib.new('sha256')
        msg = mpk['T1'] ** s[0] * mpk['T2'] ** s[1]
        sha256.update(self.group.serialize(msg))
        hd = sha256.hexdigest() 
        seed = str(hd)
        _ct = r * self.group.hash(seed, ZR) 		
        d = msk['d0'] + msk['d1'] + msk['d2']
        
        cpp = pair(g,h**(d/msk['alpha'])) ** _sk
        seed = str(cpp)
        _ctp = R * self.group.hash(seed, ZR) 		
        _ct2p = _vk
        _ct3p = self.ID_j ** (sum)
        _ct4p = _vk ** (sum)
        _C = [ct0, C, _ct, _ctp, _ct2p, _ct3p, policy, _ct4p]

        # step 6
        c = h ** (_sk + R)
        esk = self.group.random(ZR)
        epk = pair(g, _vk) ** esk
        sigma = esk + _sk*self.group.hash(str(epk)+str(c))

        # step 7
        return m, p, h_prime, b, _C, c, epk, sigma


    def verify(self, m, p, h_prime, b, C, c, epk, sigma):
        vk = C[4]  # get vk
        vk_s = C[7] # get vk_s
        b_prime = p * h_prime ** m
        base = pair(self.mpk['g'], vk)
        base_sigma_prime = epk * pair(self.mpk['g'], vk_s) ** self.group.hash(str(epk)+str(c))
	
        if (b == b_prime and base**sigma == base_sigma_prime):
            return 0
        else:
            return 1

    def adapt(self, sk_delta, m, m_prime, p, h_prime, b, C, c, epk, sigma, ID_i, policy_str):
        m_prime = self.group.random(ZR)
        _m = self.group.random(ZR)
        g = self.mpk['g']
        h = self.mpk['h']
        d = self.msk['d0'] + self.msk['d1'] + self.msk['d2']
        alpha = self.msk['alpha']
        mpk = self.mpk
        msk = self.msk
        sk_delta = self.sk_delta
        sk_prime = self.sk_delta['ssk']['sk_prime']
        ID_i = self.ID_i

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # step 2.(b)
        ctp = C[3]
        pair1 = pair(sk_delta['ssk']['sk1'], C[0][2])	# C[0][2] = ct0,3
        pair2 = pair(sk_delta['ssk']['sk0']['g_r_alpha'], C[4])	# C[4] = ct2p
        pair3 = pair(sk_delta['ssk']['sk0']['g_R'], C[0][3]) # C[0][3] = mpk['h_beta_alpha'] ** sum
        cpp = pair1 / (pair2 * pair3)
        seed = str(cpp)
        R = ctp / self.group.hash(seed, ZR)

        # step 3
        nodes = self.util.prune(C[6], self.sk_delta['attr_list']) # C[6] = ctxt['policy'] get ciphertext policy
        if not nodes:
            print ("Policy is not satisfied.")
            return None

        sk0_tmp = []
        sk0_tmp.append(sk_delta['ssk']['sk0']['h_b1_r1'])
        sk0_tmp.append(sk_delta['ssk']['sk0']['h_b2_r2'])
        sk0_tmp.append(sk_delta['ssk']['sk0']['h_r1_r2_alpha'])

        prod1_GT = 1
        prod2_GT = 1
        for i in range(self.assump_size + 1):	
            prod_H = 1
            prod_G = 1
            for node in nodes:
                attr = node.getAttributeAndIndex()
                attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
                prod_H *= sk_delta['ssk']['sk_y_t'][attr_stripped][i]
                prod_G *= C[1][attr][i]			     # C[1] = _C
            prod1_GT *= pair(sk_prime[i]*prod_H, C[0][i])
            prod2_GT *= pair(prod_G, sk0_tmp[i])
        Cp = -(prod2_GT / prod1_GT)

        sha256 = hashlib.new('sha256')
        sha256.update(self.group.serialize(Cp))
        x = sha256.hexdigest()
        seed = str(x)
        r_tmp = C[2] / self.group.hash(seed, ZR)	# C[2] = _ct

	# step 4
        s_prime = []
        sum_prime = 0	# sum = s1 + s2
        for i in range(self.assump_size):
            rand = self.group.random(ZR)
            s_prime.append(rand)
            sum_prime += rand

        _sk_prime = sum_prime
        _vk_prime = self.ID_j ** (msk['alpha']*sum_prime) # TODO add comment for ID_j

        # step 5
        sha256 = hashlib.new('sha256')
        sha256.update(self.group.serialize(R))
        hd = sha256.hexdigest() 
        seed = str(hd)
        e = self.group.hash(seed, ZR)
        r_prime = r_tmp + (m-m_prime)*e/self.sk
        p_prime = self.pk ** r_prime        

        # step 6 
        ct0 = []
        H1 = mpk['H1']
        H2 = mpk['H2']
        ct0.append(H1**s_prime[0])
        ct0.append(H2**s_prime[1])
        ct0.append(h**(sum_prime/msk['alpha']))
        ct0.append(mpk['h_beta_alpha'] ** sum_prime)

        # pre-compute hashes
        hash_table = []
        for j in range(num_cols):
            x = []
            input_for_hash1 = '0' + str(j + 1)
            for l in range(self.assump_size + 1):
                y = []
                input_for_hash2 = input_for_hash1 + str(l)
                for t in range(self.assump_size):
                    input_for_hash3 = input_for_hash2 + str(t)
                    hashed_value = self.group.hash(input_for_hash3, G1)
                    y.append(hashed_value)
                x.append(y)
            hash_table.append(x)
	
        # compute C = ct_u_l
        C = {}
        for attr, row in mono_span_prog.items():
            ct = []
            attr_stripped = self.util.strip_index(attr)  # no need, re-use not allowed
            for l in range(self.assump_size + 1):
                prod = 1
                cols = len(row)
                for t in range(self.assump_size):
                    input_for_hash = attr_stripped + str(l) + str(t)
                    prod1 = self.group.hash(input_for_hash, G1)
                    for j in range(cols):
                        prod1 *= (hash_table[j][l][t] ** row[j])
                    prod *= (prod1 ** s_prime[t])
                ct.append(prod)
            C[attr] = ct
	
        # step 7
        sha256 = hashlib.new('sha256')
        msg = mpk['T1'] ** s_prime[0] * mpk['T2'] ** s_prime[1]
        sha256.update(self.group.serialize(msg))
        hd = sha256.hexdigest() 
        seed = str(hd)
        _ct = r_prime * self.group.hash(seed, ZR) 	
        d = msk['d0'] + msk['d1'] + msk['d2']
        
        cpp = pair(g,h**(d/msk['alpha'])) ** _sk_prime
        seed = str(cpp)
        _ctp = R * self.group.hash(seed, ZR) 		
        _ct2p = _vk_prime
        _ct3p = self.ID_j ** (sum_prime)
        _ct4p = _vk_prime ** (sum_prime)
        _C = [ct0, C, _ct, _ctp, _ct2p, _ct3p, policy, _ct4p]
        C_prime = _C

        c_prime = h ** (_sk_prime + R)
        esk_prime = self.group.random(ZR)
        epk_prime = pair(g, _vk_prime) ** esk_prime
        sigma_prime = esk_prime + _sk_prime*self.group.hash(str(epk_prime)+str(c_prime))


        return m_prime, p_prime, h_prime, b, C_prime, c_prime, epk_prime, sigma_prime


    def judge(self, m, p, h_prime, b, C, c, epk, sigma, m_prime, p_prime, C_prime, c_prime, epk_prime, sigma_prime):
        rs = 0
        alpha = self.msk['alpha']
        h = self.mpk['h']
        g = self.mpk['g']
        vk = C[4]
        vk_prime = C_prime[4]

        # step 1
        b0 = p * h_prime ** m
        b1 = p_prime * h_prime ** m_prime
	
        if (b == b0 and b == b1):
            rs = 0
        else:
            rs = 1
        
        # step 2
        vk_s = C[7]
        vk_s_prime = C_prime[7]
        base = pair(g, vk)
        base_prime = pair(g, vk_prime)
        base_sigma0 = epk * pair(g, vk_s) ** self.group.hash(str(epk)+str(c))
        base_sigma1 = epk_prime * pair(g, vk_s_prime) ** self.group.hash(str(epk_prime)+str(c_prime))
        if (base**sigma == base_sigma0 and base_prime**sigma_prime == base_sigma1):
            rs = 0
        else:
            rs = 1
        
        # step 3
        delta_sk = c_prime / c
        ct_0_3 = C[0][2]
        ct_0_3_prime = C_prime[0][2]
        if (ct_0_3_prime == ct_0_3 * delta_sk):
            rs = 0
        else:
            rs = 1
        
        # step 4
        pair1 = pair(g, vk**(1/(alpha*alpha)))
        pair2 = pair(self.ID_i, C[0][2]) # C[0][2] = ct_(0,3)
        if (pair1 == pair2):
            rs = 0
        else:
            rs = 1
        

        return rs


    def TestExp(self):
        self.mpk['g'] ** self.msk['a0']












