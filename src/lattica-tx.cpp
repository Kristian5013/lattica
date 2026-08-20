// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <lattica-build-config.h> // IWYU pragma: keep

#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/license_info.h>
#include <common/system.h>
#include <compat/compat.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <core_io.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <univalue.h>
#include <util/exception.h>
#include <util/fs.h>
#include <util/moneystr.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>

#include <cstdio>
#include <functional>
#include <memory>

using util::SplitString;
using util::ToString;
using util::TrimString;
using util::TrimStringView;

static bool fCreateBlank;
static std::map<std::string,UniValue> registers;
static const int CONTINUE_EXECUTION=-1;

const TranslateFn G_TRANSLATION_FUN{nullptr};

static void SetupLatticaTxArgs(ArgsManager &argsman)
{
    SetupHelpOptions(argsman);

    argsman.AddArg("-version", "Print version and exit", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-create", "Create new, empty TX.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-json", "Select JSON output", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    argsman.AddArg("-txid", "Output only the hex-encoded transaction id of the resultant transaction.", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    SetupChainParamsBaseOptions(argsman);

    argsman.AddArg("delin=N", "Delete input N from TX", ArgsManager::ALLOW_ANY, OptionsCategory::COMMANDS);
    argsman.AddArg("delout=N", "Delete output N from TX", ArgsManager::ALLOW_ANY, OptionsCategory::COMMANDS);
    argsman.AddArg("in=TXID:VOUT(:SEQUENCE_NUMBER)", "Add input to TX", ArgsManager::ALLOW_ANY, OptionsCategory::COMMANDS);
    argsman.AddArg("locktime=N", "Set TX lock time to N", ArgsManager::ALLOW_ANY, OptionsCategory::COMMANDS);
    argsman.AddArg("nversion=N", "Set TX version to N", ArgsManager::ALLOW_ANY, OptionsCategory::COMMANDS);
    argsman.AddArg("outaddr=VALUE:ADDRESS", "Add address-based output to TX", ArgsManager::ALLOW_ANY, OptionsCategory::COMMANDS);
    argsman.AddArg("outdata=[VALUE:]DATA", "Add data-based output to TX", ArgsManager::ALLOW_ANY, OptionsCategory::COMMANDS);
    argsman.AddArg("outscript=VALUE:SCRIPT[:FLAGS]", "Add raw script output to TX. "
        "Optionally add the \"W\" flag to produce a pay-to-witness-script-hash output. "
        "Optionally add the \"S\" flag to wrap the output in a pay-to-script-hash.", ArgsManager::ALLOW_ANY, OptionsCategory::COMMANDS);
    argsman.AddArg("replaceable(=N)", "Sets Replace-By-Fee (RBF) opt-in sequence number for input N. "
        "If N is not provided, the command attempts to opt-in all available inputs for RBF. "
        "If the transaction has no inputs, this option is ignored.", ArgsManager::ALLOW_ANY, OptionsCategory::COMMANDS);

    argsman.AddArg("load=NAME:FILENAME", "Load JSON file FILENAME into register NAME", ArgsManager::ALLOW_ANY, OptionsCategory::REGISTER_COMMANDS);
    argsman.AddArg("set=NAME:JSON-STRING", "Set register NAME to given JSON-STRING", ArgsManager::ALLOW_ANY, OptionsCategory::REGISTER_COMMANDS);
}

//
// This function returns either one of EXIT_ codes when it's expected to stop the process or
// CONTINUE_EXECUTION when it's expected to continue further.
//
static int AppInitRawTx(int argc, char* argv[])
{
    SetupLatticaTxArgs(gArgs);
    std::string error;
    if (!gArgs.ParseParameters(argc, argv, error)) {
        tfm::format(std::cerr, "Error parsing command line arguments: %s\n", error);
        return EXIT_FAILURE;
    }

    // Check for chain settings (Params() calls are only valid after this clause)
    try {
        SelectParams(gArgs.GetChainType());
    } catch (const std::exception& e) {
        tfm::format(std::cerr, "Error: %s\n", e.what());
        return EXIT_FAILURE;
    }

    fCreateBlank = gArgs.GetBoolArg("-create", false);

    if (argc < 2 || HelpRequested(gArgs) || gArgs.GetBoolArg("-version", false)) {
        // First part of help message is specific to this utility
        std::string strUsage = CLIENT_NAME " lattica-tx utility version " + FormatFullVersion() + "\n";

        if (gArgs.GetBoolArg("-version", false)) {
            strUsage += FormatParagraph(LicenseInfo());
        } else {
            strUsage += "\n"
                "The lattica-tx tool is used for creating and modifying lattica transactions.\n\n"
                "lattica-tx can be used with \"<hex-tx> [commands]\" to update a hex-encoded lattica transaction, or with \"-create [commands]\" to create a hex-encoded lattica transaction.\n"
                "\n"
                "Usage: lattica-tx [options] <hex-tx> [commands]\n"
                "or:    lattica-tx [options] -create [commands]\n"
                "\n";
            strUsage += gArgs.GetHelpMessage();
        }

        tfm::format(std::cout, "%s", strUsage);

        if (argc < 2) {
            tfm::format(std::cerr, "Error: too few parameters\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    return CONTINUE_EXECUTION;
}

static void RegisterSetJson(const std::string& key, const std::string& rawJson)
{
    UniValue val;
    if (!val.read(rawJson)) {
        std::string strErr = "Cannot parse JSON for key " + key;
        throw std::runtime_error(strErr);
    }

    registers[key] = val;
}

static void RegisterSet(const std::string& strInput)
{
    // separate NAME:VALUE in string
    size_t pos = strInput.find(':');
    if ((pos == std::string::npos) ||
        (pos == 0) ||
        (pos == (strInput.size() - 1)))
        throw std::runtime_error("Register input requires NAME:VALUE");

    std::string key = strInput.substr(0, pos);
    std::string valStr = strInput.substr(pos + 1, std::string::npos);

    RegisterSetJson(key, valStr);
}

static void RegisterLoad(const std::string& strInput)
{
    // separate NAME:FILENAME in string
    size_t pos = strInput.find(':');
    if ((pos == std::string::npos) ||
        (pos == 0) ||
        (pos == (strInput.size() - 1)))
        throw std::runtime_error("Register load requires NAME:FILENAME");

    std::string key = strInput.substr(0, pos);
    std::string filename = strInput.substr(pos + 1, std::string::npos);

    FILE *f = fsbridge::fopen(filename.c_str(), "r");
    if (!f) {
        std::string strErr = "Cannot open file " + filename;
        throw std::runtime_error(strErr);
    }

    // load file chunks into one big buffer
    std::string valStr;
    while ((!feof(f)) && (!ferror(f))) {
        char buf[4096];
        int bread = fread(buf, 1, sizeof(buf), f);
        if (bread <= 0)
            break;

        valStr.insert(valStr.size(), buf, bread);
    }

    int error = ferror(f);
    fclose(f);

    if (error) {
        std::string strErr = "Error reading file " + filename;
        throw std::runtime_error(strErr);
    }

    // evaluate as JSON buffer register
    RegisterSetJson(key, valStr);
}

static CAmount ExtractAndValidateValue(const std::string& strValue)
{
    if (std::optional<CAmount> parsed = ParseMoney(strValue)) {
        return parsed.value();
    } else {
        throw std::runtime_error("invalid TX output value");
    }
}

static void MutateTxVersion(CMutableTransaction& tx, const std::string& cmdVal)
{
    const auto ver{ToIntegral<uint32_t>(cmdVal)};
    if (!ver || *ver < 1 || *ver > TX_MAX_STANDARD_VERSION) {
        throw std::runtime_error("Invalid TX version requested: '" + cmdVal + "'");
    }
    tx.version = *ver;
}

static void MutateTxLocktime(CMutableTransaction& tx, const std::string& cmdVal)
{
    const auto locktime{ToIntegral<uint32_t>(cmdVal)};
    if (!locktime) {
        throw std::runtime_error("Invalid TX locktime requested: '" + cmdVal + "'");
    }
    tx.nLockTime = *locktime;
}

static void MutateTxRBFOptIn(CMutableTransaction& tx, const std::string& strInIdx)
{
    const auto idx{ToIntegral<uint32_t>(strInIdx)};
    if (strInIdx != "" && (!idx || *idx >= tx.vin.size())) {
        throw std::runtime_error("Invalid TX input index '" + strInIdx + "'");
    }

    // set the nSequence to MAX_INT - 2 (= RBF opt in flag)
    uint32_t cnt{0};
    for (CTxIn& txin : tx.vin) {
        if (strInIdx == "" || cnt == *idx) {
            if (txin.nSequence > MAX_BIP125_RBF_SEQUENCE) {
                txin.nSequence = MAX_BIP125_RBF_SEQUENCE;
            }
        }
        ++cnt;
    }
}

template <typename T>
static T TrimAndParse(const std::string& int_str, const std::string& err)
{
    const auto parsed{ToIntegral<T>(TrimStringView(int_str))};
    if (!parsed.has_value()) {
        throw std::runtime_error(err + " '" + int_str + "'");
    }
    return parsed.value();
}

static void MutateTxAddInput(CMutableTransaction& tx, const std::string& strInput)
{
    std::vector<std::string> vStrInputParts = SplitString(strInput, ':');

    // separate TXID:VOUT in string
    if (vStrInputParts.size()<2)
        throw std::runtime_error("TX input missing separator");

    // extract and validate TXID
    auto txid{Txid::FromHex(vStrInputParts[0])};
    if (!txid) {
        throw std::runtime_error("invalid TX input txid");
    }

    static const unsigned int minTxOutSz = 9;
    static const unsigned int maxVout = MAX_BLOCK_WEIGHT / (WITNESS_SCALE_FACTOR * minTxOutSz);

    // extract and validate vout
    const std::string& strVout = vStrInputParts[1];
    const auto vout{ToIntegral<uint32_t>(strVout)};
    if (!vout || *vout > maxVout) {
        throw std::runtime_error("invalid TX input vout '" + strVout + "'");
    }

    // extract the optional sequence number
    uint32_t nSequenceIn = CTxIn::SEQUENCE_FINAL;
    if (vStrInputParts.size() > 2) {
        nSequenceIn = TrimAndParse<uint32_t>(vStrInputParts.at(2), "invalid TX sequence id");
    }

    // append to transaction input list
    CTxIn txin{*txid, *vout, CScript{}, nSequenceIn};
    tx.vin.push_back(txin);
}

static void MutateTxAddOutAddr(CMutableTransaction& tx, const std::string& strInput)
{
    // Separate into VALUE:ADDRESS
    std::vector<std::string> vStrInputParts = SplitString(strInput, ':');

    if (vStrInputParts.size() != 2)
        throw std::runtime_error("TX output missing or too many separators");

    // Extract and validate VALUE
    CAmount value = ExtractAndValidateValue(vStrInputParts[0]);

    // extract and validate ADDRESS
    const std::string& strAddr = vStrInputParts[1];
    CTxDestination destination = DecodeDestination(strAddr, Params());
    if (!IsValidDestination(destination)) {
        throw std::runtime_error("invalid TX output address");
    }
    CScript scriptPubKey = GetScriptForDestination(destination);

    // construct TxOut, append to transaction output list
    CTxOut txout(value, scriptPubKey);
    tx.vout.push_back(txout);
}

static void MutateTxAddOutData(CMutableTransaction& tx, const std::string& strInput)
{
    CAmount value = 0;

    // separate [VALUE:]DATA in string
    size_t pos = strInput.find(':');

    if (pos==0)
        throw std::runtime_error("TX output value not specified");

    if (pos == std::string::npos) {
        pos = 0;
    } else {
        // Extract and validate VALUE
        value = ExtractAndValidateValue(strInput.substr(0, pos));
        ++pos;
    }

    // extract and validate DATA
    const std::string strData{strInput.substr(pos, std::string::npos)};

    if (!IsHex(strData))
        throw std::runtime_error("invalid TX output data");

    std::vector<unsigned char> data = ParseHex(strData);

    CTxOut txout(value, CScript() << OP_RETURN << data);
    tx.vout.push_back(txout);
}

static void MutateTxAddOutScript(CMutableTransaction& tx, const std::string& strInput)
{
    // separate VALUE:SCRIPT[:FLAGS]
    std::vector<std::string> vStrInputParts = SplitString(strInput, ':');
    if (vStrInputParts.size() < 2)
        throw std::runtime_error("TX output missing separator");

    // Extract and validate VALUE
    CAmount value = ExtractAndValidateValue(vStrInputParts[0]);

    // extract and validate script
    const std::string& strScript = vStrInputParts[1];
    CScript scriptPubKey = ParseScript(strScript);

    // Extract FLAGS
    bool bSegWit = false;
    bool bScriptHash = false;
    if (vStrInputParts.size() == 3) {
        const std::string& flags = vStrInputParts.back();
        bSegWit = (flags.find('W') != std::string::npos);
        bScriptHash = (flags.find('S') != std::string::npos);
    }

    if (scriptPubKey.size() > MAX_SCRIPT_SIZE) {
        throw std::runtime_error(strprintf(
                    "script exceeds size limit: %d > %d", scriptPubKey.size(), MAX_SCRIPT_SIZE));
    }

    if (bSegWit) {
        scriptPubKey = GetScriptForDestination(WitnessV0ScriptHash(scriptPubKey));
    }
    if (bScriptHash) {
        if (scriptPubKey.size() > MAX_SCRIPT_ELEMENT_SIZE) {
            throw std::runtime_error(strprintf(
                        "redeemScript exceeds size limit: %d > %d", scriptPubKey.size(), MAX_SCRIPT_ELEMENT_SIZE));
        }
        scriptPubKey = GetScriptForDestination(ScriptHash(scriptPubKey));
    }

    // construct TxOut, append to transaction output list
    CTxOut txout(value, scriptPubKey);
    tx.vout.push_back(txout);
}

static void MutateTxDelInput(CMutableTransaction& tx, const std::string& strInIdx)
{
    const auto idx{ToIntegral<uint32_t>(strInIdx)};
    if (!idx || idx >= tx.vin.size()) {
        throw std::runtime_error("Invalid TX input index '" + strInIdx + "'");
    }
    tx.vin.erase(tx.vin.begin() + *idx);
}

static void MutateTxDelOutput(CMutableTransaction& tx, const std::string& strOutIdx)
{
    const auto idx{ToIntegral<uint32_t>(strOutIdx)};
    if (!idx || idx >= tx.vout.size()) {
        throw std::runtime_error("Invalid TX output index '" + strOutIdx + "'");
    }
    tx.vout.erase(tx.vout.begin() + *idx);
}

static void MutateTx(CMutableTransaction& tx, const std::string& command,
                     const std::string& commandVal)
{
    if (command == "nversion")
        MutateTxVersion(tx, commandVal);
    else if (command == "locktime")
        MutateTxLocktime(tx, commandVal);
    else if (command == "replaceable") {
        MutateTxRBFOptIn(tx, commandVal);
    }

    else if (command == "delin")
        MutateTxDelInput(tx, commandVal);
    else if (command == "in")
        MutateTxAddInput(tx, commandVal);

    else if (command == "delout")
        MutateTxDelOutput(tx, commandVal);
    else if (command == "outaddr")
        MutateTxAddOutAddr(tx, commandVal);
    else if (command == "outscript")
        MutateTxAddOutScript(tx, commandVal);
    else if (command == "outdata")
        MutateTxAddOutData(tx, commandVal);

    else if (command == "load")
        RegisterLoad(commandVal);

    else if (command == "set")
        RegisterSet(commandVal);

    else
        throw std::runtime_error("unknown command");
}

static void OutputTxJSON(const CTransaction& tx)
{
    UniValue entry(UniValue::VOBJ);
    TxToUniv(tx, /*block_hash=*/uint256(), entry);

    std::string jsonOutput = entry.write(4);
    tfm::format(std::cout, "%s\n", jsonOutput);
}

static void OutputTxHash(const CTransaction& tx)
{
    std::string strHexHash = tx.GetHash().GetHex(); // the hex-encoded transaction hash (aka the transaction id)

    tfm::format(std::cout, "%s\n", strHexHash);
}

static void OutputTxHex(const CTransaction& tx)
{
    std::string strHex = EncodeHexTx(tx);

    tfm::format(std::cout, "%s\n", strHex);
}

static void OutputTx(const CTransaction& tx)
{
    if (gArgs.GetBoolArg("-json", false))
        OutputTxJSON(tx);
    else if (gArgs.GetBoolArg("-txid", false))
        OutputTxHash(tx);
    else
        OutputTxHex(tx);
}

static std::string readStdin()
{
    char buf[4096];
    std::string ret;

    while (!feof(stdin)) {
        size_t bread = fread(buf, 1, sizeof(buf), stdin);
        ret.append(buf, bread);
        if (bread < sizeof(buf))
            break;
    }

    if (ferror(stdin))
        throw std::runtime_error("error reading stdin");

    return TrimString(ret);
}

static int CommandLineRawTx(int argc, char* argv[])
{
    std::string strPrint;
    int nRet = 0;
    try {
        // Skip switches; Permit common stdin convention "-"
        while (argc > 1 && IsSwitchChar(argv[1][0]) &&
               (argv[1][1] != 0)) {
            argc--;
            argv++;
        }

        CMutableTransaction tx;
        int startArg;

        if (!fCreateBlank) {
            // require at least one param
            if (argc < 2)
                throw std::runtime_error("too few parameters");

            // param: hex-encoded lattica transaction
            std::string strHexTx(argv[1]);
            if (strHexTx == "-")                 // "-" implies standard input
                strHexTx = readStdin();

            if (!DecodeHexTx(tx, strHexTx, true))
                throw std::runtime_error("invalid transaction encoding");

            startArg = 2;
        } else
            startArg = 1;

        for (int i = startArg; i < argc; i++) {
            std::string arg = argv[i];
            std::string key, value;
            size_t eqpos = arg.find('=');
            if (eqpos == std::string::npos)
                key = arg;
            else {
                key = arg.substr(0, eqpos);
                value = arg.substr(eqpos + 1);
            }

            MutateTx(tx, key, value);
        }

        OutputTx(CTransaction(tx));
    }
    catch (const std::exception& e) {
        strPrint = std::string("error: ") + e.what();
        nRet = EXIT_FAILURE;
    }
    catch (...) {
        PrintExceptionContinue(nullptr, "CommandLineRawTx()");
        throw;
    }

    if (strPrint != "") {
        tfm::format(nRet == 0 ? std::cout : std::cerr, "%s\n", strPrint);
    }
    return nRet;
}

MAIN_FUNCTION
{
    SetupEnvironment();

    try {
        int ret = AppInitRawTx(argc, argv);
        if (ret != CONTINUE_EXECUTION)
            return ret;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitRawTx()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(nullptr, "AppInitRawTx()");
        return EXIT_FAILURE;
    }

    int ret = EXIT_FAILURE;
    try {
        ret = CommandLineRawTx(argc, argv);
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "CommandLineRawTx()");
    } catch (...) {
        PrintExceptionContinue(nullptr, "CommandLineRawTx()");
    }
    return ret;
}
