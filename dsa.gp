keypairs = [];

GenerateRandom(max) = {
    random_number = random(max);

    if(((random_number > 0) && (random_number == max)),
    GenerateRandom(max),

    return(random_number);
    );
}

GeneratePrime(x, y) = {
    random_number = random(10240);
    p = 0;

    if(((length(binary(random_number)) > x) && (isprime(random_number) == 1)),
    p = random_number,

    GeneratePrime(x, y);
    );

    q = vecmax(factorint(p-1)[, 1]);
    if((length(binary(q)) < y),
    GeneratePrime(x, y),

    return([p, q])    
    );
}

GenerateG(p, q) = {
    h = GenerateRandom(p-1);
    e = (p-1)/q;
    g = lift(Mod((h^e), p));

    if((g <= 1), GenerateG(p, q), return(g););
}

isPrimeRoot(q, p) = {
    factors = factor(p-1);
    y = matsize(factors);

    for(i = 1, y[1],
    if((Mod(1, p) == Mod(q,p)^((p-1)/factors[i,1])),
    return(0),
    return(1));
    );
}


Keygen(x, y) = {
    pq_pair = GeneratePrime(x, y);

    p = pq_pair[1];
    q = pq_pair[2];
    g = GenerateG(p, q);
    X = GenerateRandom(q);
    Y = lift(Mod((g^X), p));

    print("P = ", p, "\n\t|P|_2 = ", length(binary(p)), "\nQ = ", q, "\n\t|Q|_2 = ", length(binary(q)));
    print("Public Key: \n\tg = ", g, "\n\ty = ", Y, "\n\nPrivate Key:\n\tx = ", X);
    keypairs = [p, q, g, X, Y];
}

Sign(m) = {
    k = GenerateRandom(keypairs[2]);
    
    r = lift(Mod(((lift(Mod((keypairs[3]^k), keypairs[1])))), keypairs[2]));
    s = lift((Mod(((k^-1) * (m + (r * keypairs[4]))), keypairs[2])));
    
    if(((isPrimeRoot(r, keypairs[2]) == 1) && (isPrimeRoot(s, keypairs[2]) == 1) && (r < q) && (s < q)),
    print("Signature: (", r, ", ", s, ")"), 

    Sign(m);
    );


}

Verify(m, r, s) = {
    w = lift(Mod((s^-1), keypairs[2]));

    u1 = lift(Mod((m*w), keypairs[2]));
    u2 = lift(Mod((r*w), keypairs[2]));

    v = lift(Mod((lift(Mod(((keypairs[3]^u1)*(keypairs[5]^u2)), keypairs[1]))), keypairs[2]));

    if((v == r),
    print("Verified OK"),
    print("Reject");
    );
}

Help() = {
    print("\nDigital Signature Algorithm\n\nEnter:\n\tKeygen(x, y): to produce secret and public key parameters\n\twhere |P|_2 >= x and |Q|_2 >= y\n\n\tSign(m): to sign a message m using the private key\n\n
    \tVerify(m, r, s): to verify a message m with signature (r, s)\n\n\tHelp: this screen");
}

Help()
