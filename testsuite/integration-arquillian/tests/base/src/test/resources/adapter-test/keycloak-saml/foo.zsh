#!zsh

function changepass() {

  KEYSTORE=$1

  ALIAS=$(echo store123 | keytool -v -list -keystore $KEYSTORE|grep 'Alias name: http' |cut -d $' ' -f3)
  keytool -keypasswd  -alias $ALIAS  -keystore $KEYSTORE
}


