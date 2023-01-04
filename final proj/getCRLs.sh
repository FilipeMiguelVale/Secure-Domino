#bin/bash
wget -r https://pki.cartaodecidadao.pt/publico/lrc/
echo "Fetch all CRL's"
cd pki.cartaodecidadao.pt/publico/lrc/
rm *.html cc_sub-ec_cidadao_assinatura_*
echo "Removed extra files"
cp * ../../../crls/
cd ../../../ && rm -r pki.cartaodecidadao.pt
