cat electrum-dogecoin-private-keys.csv | grep p2
cat electrum-dogecoin-private-keys.csv | grep p2 > p2.txt
cat p2.txt | cut -c 42-100 > keys.txt
echo ''
echo ''
echo ''
cat keys.txt
