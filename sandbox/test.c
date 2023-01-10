#define SETF (1<<12)
#define CHECKF (1ull << 38)

unsigned long long is_setdm(unsigned long long bits, unsigned long long result)
{
    result |= (bits & CHECKF) / CHECKF * SETF;
    return result;
}

unsigned long long is_setto(unsigned long long bits, unsigned long long result)
{
    result |= bits & CHECKF ? SETF : 0;
    return result;
}

unsigned long long is_setif(unsigned long long bits, unsigned long long result)
{
    if (!!(bits & CHECKF))
        result |= SETF;
    return result;
}

