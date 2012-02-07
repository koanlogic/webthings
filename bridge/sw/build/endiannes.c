int main(void)
{
    short int word = 0x0001;
    char *byte = (char *) &word;

    /* Big endian is '0', little endian is '1' */
    return byte[0];
}
