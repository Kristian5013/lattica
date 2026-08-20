#include <util/moneystr.h>
#include <consensus/amount.h>
#include <cstdio>
int g_fail=0;
void Check(const char* n, bool ok){ std::printf("[%s] %s\n", ok?"PASS":"FAIL", n); if(!ok)++g_fail; }
int main(){
    Check("FormatMoney(COIN)==1.00", FormatMoney(COIN)=="1.00");
    Check("FormatMoney(0)==0.00", FormatMoney(0)=="0.00");
    Check("FormatMoney(COIN/2)==0.50", FormatMoney(COIN/2)=="0.50");
    Check("FormatMoney(-COIN)==-1.00", FormatMoney(-COIN)=="-1.00");
    Check("FormatMoney(50*COIN)==50.00", FormatMoney(50*COIN)=="50.00");
    Check("ParseMoney(\"1.00\")==COIN", ParseMoney("1.00")==std::optional<CAmount>(COIN));
    Check("ParseMoney(\"0.0034\")==340000", ParseMoney("0.0034")==std::optional<CAmount>(340000));
    Check("ParseMoney(\"50\")==50*COIN", ParseMoney("50")==std::optional<CAmount>(50*COIN));
    Check("ParseMoney(\"21000001\") out of range -> nullopt", ParseMoney("21000001")==std::nullopt);
    Check("ParseMoney(\"abc\") -> nullopt", ParseMoney("abc")==std::nullopt);
    Check("roundtrip 1.23456789", ParseMoney("1.23456789")==std::optional<CAmount>(COIN+23456789));
    std::printf("%s\n", g_fail==0?"ALL PASS":"FAILURES");
    return g_fail==0?0:1;
}
