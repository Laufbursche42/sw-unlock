// Segway-Ninebot Scooter Tool - Web Bluetooth BLE client  (v3)
// Encryption2 (AES-128 CTR + CBC-MAC, SN + non-SN) and legacy Protocol-2 fallback.
// Crypto/transport/auth byte-verified against: codeberg NootNooot/segway-ninebot-ble-cli
//   (nb_crypto.py, nb_protocol.py, boards.json), NinebotCrypto, py9b, CamiAlfa/M365-BLE-PROTOCOL.
//
// IMPORTANT: register *meanings* below come from community references that (per their own authors)
// were NEVER tested against a real Segway-Ninebot vehicle. Read values first and sanity-check them
// BEFORE writing anything. [OK] = consistent across >=2 refs. [?] = plausible, unverified.
//
// Per-model family profiles (from ninebot-docs device configs, 2026-10-14):
//   eseries (DIS 0x01, Gen2): E150S/E250S/eScooter E/N - speed-limit 0x93 whole km/h [OK]
//   vcu     (VCU 0x16+TFT 0x23, Gen3): GT3/ZT3 Pro/Max G3/F3 - setMaxSpeed 0x46; ONLY family with BLE wSN (region)
//   kick/ctrl families (ESC 0x20): Max G2/F2*, ES/E/Max/C2 Pro, P-series, D/F/Air, F65/G65 - speed reg varies per model
// IMPORTANT: only the E-series 0x93 speed value is byte-proven; every other register/value is community-sourced
// and unverified on a real vehicle. The model picker selects the right board+register; verify values by reading first.
'use strict';

const BUILD = 'v4';

// ---- BLE service UUIDs ----
const NINEBOT_SVC='6e400001-0000-0000-006e-696e65626f74', NINEBOT_WR='6e400002-0000-0000-006e-696e65626f74', NINEBOT_NTFY='6e400004-0000-0000-006e-696e65626f74';
const NORDIC_SVC='6e400001-b5a3-f393-e0a9-e50e24dcca9e', NORDIC_WR='6e400002-b5a3-f393-e0a9-e50e24dcca9e', NORDIC_NTFY='6e400003-b5a3-f393-e0a9-e50e24dcca9e';
const ISSC_SVC='49535343-fe7d-4ae5-8fa9-9fafd205e455', ISSC_NTFY='49535343-1e4d-4bd9-ba61-23c647249616', ISSC_WR='49535343-aca3-481c-91ec-d85e28a60318';
const HMSOFT_SVC='0000ffe0-0000-1000-8000-00805f9b34fb', HMSOFT_NTFY='0000ffe1-0000-1000-8000-00805f9b34fb';
const FEE7_SVC='0000fee7-0000-1000-8000-00805f9b34fb', FEC7_WR='0000fec7-0000-1000-8000-00805f9b34fb', FEC8_NTFY='0000fec8-0000-1000-8000-00805f9b34fb';
const VENDOR_16BIT=[];
for(const base of ['fc','fd','fe','ff']) for(let i=0;i<256;i++) VENDOR_16BIT.push('0000'+base+i.toString(16).padStart(2,'0')+'-0000-1000-8000-00805f9b34fb');
const OPTIONAL_SERVICES=[NINEBOT_SVC,NORDIC_SVC,ISSC_SVC,HMSOFT_SVC,FEE7_SVC,...VENDOR_16BIT];
const NAME_PREFIXES=['NB','Ninebot','ninebot','S1D','SNSC','N2','N3','N4','N5','N6','N7','N8','N9','ES','Max','F20','F25','F30','F40','GT','P100','P65','D18','D28','D38','E2','E25','E45','Segway'];
const WRITE_UUIDS={ninebot:NINEBOT_WR,nordic:NORDIC_WR,issc:ISSC_WR,hmsoft:HMSOFT_SVC,fee7:FEC7_WR};
const NOTIFY_UUIDS={ninebot:NINEBOT_NTFY,nordic:NORDIC_NTFY,issc:ISSC_NTFY,hmsoft:HMSOFT_NTFY,fee7:FEC8_NTFY};

// ---- Protocol generation (crypto) ----
const FW_DATA=new Uint8Array([0x97,0xCF,0xB8,0x02,0x84,0x41,0x43,0xDE,0x56,0x00,0x2B,0x3B,0x34,0x78,0x0A,0x5D]); // libnbcrypto.so @0x45A80 (GEN2 non-SN) [OK]
const GEN={ gen3:{sync2:0xB5,ecb:new Uint8Array(16)}, gen2:{sync2:0xA5,ecb:FW_DATA.slice(0,16)} };
let proto=GEN.gen3;

const CMD={ READ:0x01, WRITE:0x02, WRITE_NR:0x03, READ_RESP:0x04, WRITE_RESP:0x05, PRE_COMM:0x5B, SET_PWD:0x5C, AUTH:0x5D, WRITE_SN:0x18, UNLOCK:0x63, ACTIVATE:0x57 };
const AUTH_TARGET=0x04; // BLE board for Encryption2 handshake [OK] (0x21 = legacy plaintext only)

// ==== Register schemes (family-dependent). All [?] unless noted; never hardware-tested. ====
const BMS_E2=[ {field:'soc',reg:0x32,len:2,conf:'OK'}, {field:'voltage',reg:0x1A,len:2,scale:0.01,conf:'?'}, {field:'cycles',reg:0x1B,len:2,conf:'?'} ];
const BMS_LEG_BLOCK={reg:0x31,len:10}; // restCap,soc,current(/100),voltage(/100),temp1,temp2  (M365, byte-validated) [OK-M365]
const BMS_LEG_CELLS={reg:0x40,len:20}; // 10 x u16le mV [OK-M365]

// ---- Telemetry read sets (per board family) ----
const TELE_DIS=[ // DIS 0x01 (E-Serie)
  {key:'serial',    t:0x01,reg:0x10,len:14,type:'ascii',conf:'?'},
  {key:'fwVer',     t:0x01,reg:0x1A,len:2, type:'ver',  conf:'?'},
  {key:'speed',     t:0x01,reg:0x26,len:2, type:'u16le',scale:0.1, conf:'OK',poll:true},
  {key:'battery',   t:0x01,reg:0xB5,len:2, type:'u16le',conf:'OK',poll:true},
  {key:'speedLimit',t:0x01,reg:0x93,len:2, type:'u16le',conf:'OK'},   // whole km/h, LE [OK]
  {key:'mode',      t:0x01,reg:0x74,len:2, type:'u16le',conf:'?'},    // setCfgMode enum (ground-truth reg)
  {key:'odo',       t:0x01,reg:0xB7,len:4, type:'u32le',scale:0.001,conf:'OK'},
  {key:'trip',      t:0x01,reg:0xB9,len:4, type:'u32le',scale:0.001,conf:'?'},
  {key:'range',     t:0x01,reg:0x25,len:2, type:'u16le',scale:0.1, conf:'?'},
];
const TELE_ESC=[ // ESC/ctrl 0x20 (kick/M365 + abgeleitete)
  {key:'serial',    t:0x20,reg:0x10,len:14,type:'ascii',conf:'?'},
  {key:'fwVer',     t:0x20,reg:0x1A,len:2, type:'ver',  conf:'?'},
  {key:'speed',     t:0x20,reg:0xB5,len:2, type:'u16le',scale:0.1,conf:'OK',poll:true},
  {key:'battery',   t:0x20,reg:0xB4,len:2, type:'u16le',conf:'OK',poll:true},
  {key:'speedLimit',t:0x20,reg:0xBC,len:2, type:'u16le',scale:0.1,conf:'?'},
  {key:'odo',       t:0x20,reg:0xB7,len:4, type:'u32le',scale:0.001,conf:'OK'},
  {key:'trip',      t:0x20,reg:0xB9,len:2, type:'u16le',scale:0.01, conf:'OK'},
];
const TELE_VCU=[ // VCU 0x16 (GT3/ZT3/MaxG3/F3) - nur belegte Register; Rest über Roh-Konsole
  {key:'serial',    t:0x16,reg:0x10,len:14,type:'ascii',conf:'?'},
  {key:'speedLimit',t:0x16,reg:0x46,len:2, type:'u16le',conf:'?'},   // setMaxSpeed-Rücklesewert
];

// ---- Family profiles. tele/bms/settings + serialWrite + acc(info-only) + default gen. ----
// settings.<x>=null → Hebel für dieses Modell nicht verfügbar (UI blendet ihn aus).
const PROFILES={
  eseries:{ tele:TELE_DIS, bms:[0x07,0x06,0x05], bmsLegacy:false, serialWrite:false, serialBoard:0x01, acc:{cmd:0x64,board:0x04,token:true}, gen:'gen2',
    settings:{ speed:{t:0x01,reg:0x93,enc:'u16le_whole',conf:'OK'}, speedOff:{t:0x01,reg:0x93,data:[0,0]},
      mode:{t:0x01,reg:0x74,enc:'u16le_map',map:[0,1,2],conf:'?'}, kers:{t:0x02,reg:0x54,enc:'u16le_map',map:[0,1,2],conf:'?'},
      cruise:null, taillight:null, volume:{t:0x01,reg:0x75,enc:'u16le_low',conf:'?'} } },
  vcu:{ tele:TELE_VCU, bms:[0x07,0x06,0x05], bmsLegacy:false, serialWrite:true, serialBoard:0x16, acc:{cmd:0x79,board:0x16,token:true}, gen:'gen3',
    settings:{ speed:{t:0x16,reg:0x46,enc:'u16le_whole',conf:'?'}, speedOff:null,
      mode:{t:0x16,reg:0x5A,enc:'u16le_map',map:[0,1,2],conf:'?'}, kers:{t:0x16,reg:0x70,enc:'u16le_map',map:[0,1,2],conf:'?'},
      cruise:null, taillight:{t:0x16,reg:0x5D,enc:'u16le_map',map:[0,2],conf:'?'}, volume:null } },
  gt1:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'gen3',
    settings:{ speed:{t:0x20,reg:0x94,enc:'u16le_whole',conf:'?'}, speedOff:null,
      mode:{t:0x20,reg:0x46,enc:'u16le_map',map:[0,1,2],conf:'?'}, kers:{t:0x20,reg:0x89,enc:'u16le_map',map:[0,1,2],conf:'?'},
      cruise:null, taillight:null, volume:null } },
  gt2:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'gen3',
    settings:{ speed:null, speedOff:null,
      mode:{t:0x20,reg:0x46,enc:'u16le_map',map:[0,1,2],conf:'?'}, kers:{t:0x20,reg:0x89,enc:'u16le_map',map:[0,1,2],conf:'?'},
      cruise:null, taillight:null, volume:null } },
  kickmodern:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:{cmd:0x1E,board:0x04,token:true}, gen:'gen3',
    settings:{ speed:{t:0x20,reg:0x90,enc:'u16le_whole',conf:'?'}, speedOff:null,
      mode:{t:0x20,reg:0x75,enc:'u16le_map',map:[1,0,2],conf:'?'}, kers:{t:0x20,reg:0x7B,enc:'u16le_map',map:[0,1,2],conf:'OK'},
      cruise:{t:0x20,reg:0xF0,enc:'u16le_map',map:[0,1],conf:'?'}, taillight:null, volume:null } },
  e2pro:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:{cmd:0x1E,board:0x04,token:true}, gen:'gen3',
    settings:{ speed:{t:0x20,reg:0x94,enc:'u16le_whole',conf:'?'}, speedOff:null,
      mode:{t:0x20,reg:0x75,enc:'u16le_map',map:[1,0,2],conf:'?'}, kers:{t:0x20,reg:0x76,enc:'u16le_map',map:[0,1,2],conf:'?'},
      cruise:{t:0x20,reg:0x7C,enc:'u16le_map',map:[0,1],conf:'?'}, taillight:{t:0x20,reg:0x7D,enc:'u16le_map',map:[0,2],conf:'?'}, volume:null } },
  e3:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x02, acc:{cmd:0x6A,board:0x04,token:true}, gen:'gen3',
    settings:{ speed:{t:0x02,reg:0x94,enc:'u16le_whole',conf:'?'}, speedOff:null,
      mode:null, kers:{t:0x02,reg:0x76,enc:'u16le_map',map:[0,1,2],conf:'?'},
      cruise:{t:0x02,reg:0x7C,enc:'u16le_map',map:[0,1],conf:'?'}, taillight:{t:0x02,reg:0x7A,enc:'u16le_map',map:[0,2],conf:'?'}, volume:null } },
  es_e:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'legacy',
    settings:{ speed:{t:0x20,reg:0x74,enc:'u16le_whole',conf:'?'}, speedOff:null,
      mode:{t:0x20,reg:0x75,enc:'u16le_map',map:[1,0,2],conf:'?'}, kers:{t:0x20,reg:0x7B,enc:'u16le_map',map:[0,1,2],conf:'OK'},
      cruise:{t:0x20,reg:0x7C,enc:'u16le_map',map:[0,1],conf:'OK'}, taillight:null, volume:null } },
  max:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'gen3',
    settings:{ speed:{t:0x20,reg:0x90,enc:'u16le_whole',conf:'?'}, speedOff:null,
      mode:null, kers:{t:0x20,reg:0x7B,enc:'u16le_map',map:[0,1,2],conf:'OK'},
      cruise:{t:0x20,reg:0x7C,enc:'u16le_map',map:[0,1],conf:'OK'}, taillight:null, volume:null } },
  c2pro:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'legacy',
    settings:{ speed:{t:0x20,reg:0x73,enc:'u16le_x10',pre:{reg:0x72,data:[1,0]},conf:'?'}, speedOff:{t:0x20,reg:0x72,data:[0,0]},
      mode:{t:0x20,reg:0x75,enc:'u16le_map',map:[1,0,2],conf:'?'}, kers:{t:0x20,reg:0x76,enc:'u16le_map',map:[0,1,2],conf:'?'},
      cruise:{t:0x20,reg:0x7C,enc:'u16le_map',map:[0,1],conf:'OK'}, taillight:{t:0x20,reg:0x8D,enc:'u16le_map',map:[0,2],conf:'?'}, volume:null } },
  kickgeneric:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'gen3',
    settings:{ speed:{t:0x20,reg:0x73,enc:'u16le_x10',pre:{reg:0x72,data:[1,0]},conf:'?'}, speedOff:{t:0x20,reg:0x72,data:[0,0]},
      mode:{t:0x20,reg:0x75,enc:'u16le_map',map:[1,0,2],conf:'?'}, kers:{t:0x20,reg:0x7B,enc:'u16le_map',map:[0,1,2],conf:'OK'},
      cruise:{t:0x20,reg:0x7C,enc:'u16le_map',map:[0,1],conf:'OK'}, taillight:{t:0x20,reg:0x7D,enc:'u16le_map',map:[0,2],conf:'OK'}, volume:null } },
  pseries:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'gen3',
    settings:{ speed:null, speedOff:null,
      mode:{t:0x20,reg:0x46,enc:'u16le_map',map:[0,1,2],conf:'?'}, kers:{t:0x20,reg:0x7B,enc:'u16le_map',map:[0,1,2],conf:'?'},
      cruise:{t:0x20,reg:0x7C,enc:'u16le_map',map:[0,1],conf:'?'}, taillight:null, volume:null } },
  e2:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'legacy',
    settings:{ speed:null, speedOff:null, mode:null,
      kers:{t:0x20,reg:0x76,enc:'u16le_map',map:[0,1,2],conf:'?'}, cruise:{t:0x20,reg:0x7C,enc:'u16le_map',map:[0,1],conf:'?'},
      taillight:{t:0x20,reg:0x8D,enc:'u16le_map',map:[0,2],conf:'?'}, volume:null } },
  minimal:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'legacy',
    settings:{ speed:null, speedOff:null, mode:null,
      kers:{t:0x20,reg:0x7B,enc:'u16le_map',map:[0,1,2],conf:'OK'}, cruise:{t:0x20,reg:0x7C,enc:'u16le_map',map:[0,1],conf:'OK'},
      taillight:null, volume:null } },
  f65g65:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'gen3',
    settings:{ speed:null, speedOff:null, mode:null,
      kers:{t:0x20,reg:0x7B,enc:'u16le_map',map:[0,1,2],conf:'?'}, cruise:{t:0x20,reg:0x7C,enc:'u16le_map',map:[0,1],conf:'?'},
      taillight:null, volume:null } },
  st2pro:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'gen3',
    settings:{ speed:null, speedOff:null,
      mode:{t:0x20,reg:0x46,enc:'u16le_map',map:[0,1,2],conf:'?'}, kers:{t:0x20,reg:0x89,enc:'u16le_map',map:[0,1,2],conf:'?'},
      cruise:null, taillight:null, volume:null } },
  minilite:{ tele:TELE_ESC, bms:[0x22,0x23], bmsLegacy:true, serialWrite:false, serialBoard:0x20, acc:null, gen:'gen3',
    settings:{ speed:{t:0x20,reg:0x74,enc:'u16le_whole',conf:'?'}, speedOff:null,
      mode:{t:0x20,reg:0xE0,enc:'u16le_map',map:[0,1,2],conf:'?'}, kers:null, cruise:null, taillight:null, volume:null } },
};

// ---- Model list, grouped. gkey = i18n optgroup key; p = profile key. Names are proper nouns (not translated). ----
const MODEL_GROUPS=[
  {gkey:'grpFallback', models:[
    {name:'Unbekannt - DIS/0x93 (E-Serie-Typ)', p:'eseries'},
    {name:'Unbekannt - Kick/ESC (M365-Typ)',    p:'kickgeneric'} ]},
  {gkey:'grpE', models:[
    {name:'E150S', p:'eseries'}, {name:'E250S', p:'eseries'},
    {name:'eScooter E', p:'eseries'}, {name:'eScooter N', p:'eseries'} ]},
  {gkey:'grpVcu', models:[
    {name:'GT3', p:'vcu'}, {name:'GT3 D (DE)', p:'vcu'}, {name:'GT3 Pro', p:'vcu'},
    {name:'ZT3 Pro', p:'vcu'}, {name:'Max G3', p:'vcu'}, {name:'Max G3 Plus', p:'vcu'}, {name:'eKickScooter F3', p:'vcu'} ]},
  {gkey:'grpGt12', models:[ {name:'GT1', p:'gt1'}, {name:'GT2', p:'gt2'} ]},
  {gkey:'grpKick3', models:[
    {name:'Max G2', p:'kickmodern'}, {name:'F2', p:'kickmodern'}, {name:'F2 Plus', p:'kickmodern'},
    {name:'F2 Pro', p:'kickmodern'}, {name:'E2 Pro', p:'e2pro'}, {name:'eKickScooter E3', p:'e3'} ]},
  {gkey:'grpLegacy', models:[
    {name:'KickScooter Max', p:'max'}, {name:'ES (ES1/ES2/ES4)', p:'es_e'}, {name:'E (E22/E25/E45)', p:'es_e'},
    {name:'C2 Pro', p:'c2pro'}, {name:'E2', p:'e2'}, {name:'E2 Plus', p:'e2'} ]},
  {gkey:'grpP', models:[ {name:'P100S', p:'pseries'}, {name:'P65', p:'pseries'} ]},
  {gkey:'grpSmall', models:[
    {name:'KickScooter F (F20/F25/...)', p:'minimal'}, {name:'Air (T15)', p:'minimal'},
    {name:'D18E/D28E/D38E', p:'minimal'}, {name:'F65', p:'f65g65'}, {name:'G65', p:'f65g65'},
    {name:'ST2 Pro', p:'st2pro'}, {name:'miniLITE', p:'minilite'} ]},
];
const MODELS=MODEL_GROUPS.flatMap(g=>g.models);
let scheme=PROFILES.eseries;
let currentModel=MODELS[0];

// ---- State ----
let device=null,server=null,svc=null,writeChar=null,notifyChar=null;
let connected=false,authDone=false,encrypted=true;
let authParam=null,serial=null,sessionKey=null,password=null;
let counter=0,bleName='',pollTimer=null,readMap=new Map();
let rawWatch=new Set();
const INFO={}, BMS=[{},{},{}];

// ==== Raw register console (expert) - probe ANY board/register without the app ====
// Board addresses span both families; user picks which applies to their model.
const RAW_BOARDS=[
  {v:0x01,n:'DIS / Dashboard (0x01) - modern (E-Serie)'},
  {v:0x02,n:'MCU / Motor-Controller (0x02) - modern'},
  {v:0x04,n:'BLE (0x04) - modern'},
  {v:0x05,n:'BMS 3 (0x05) - modern'},
  {v:0x06,n:'BMS 2 (0x06) - modern'},
  {v:0x07,n:'BMS 1 (0x07) - modern'},
  {v:0x09,n:'ECU / VCU (0x09) - modern (E-Serie)'},
  {v:0x11,n:'HEP / Beleuchtung (0x11) - modern'},
  {v:0x16,n:'VCU (0x16) - modern (GT3/ZT3)'},
  {v:0x20,n:'ESC / Controller (0x20) - kick/M365'},
  {v:0x21,n:'BLE (0x21) - kick/M365'},
  {v:0x22,n:'BMS (0x22) - kick/M365'},
  {v:0x23,n:'0x23 - BMS2 (kick) / TFT-Dashboard (GT3)'},
];
// Candidate "speed levers" + useful reads. ✎=write preset, ⤓=read preset. Values in little-endian hex.
// All UNVERIFIED on a live vehicle unless the label says otherwise - read & sanity-check before writing.
// Compiled from public register maps (NootNooot/segway-ninebot-ble-cli, nootnooot docs, py9b, M365).
const MODERN_PRESETS=[
  // reads - speed & caps
  {label:'⤓ Aktuelle Geschwindigkeit (DIS 0x26 ×0.1)',   board:0x01,reg:0x26,len:2},
  {label:'⤓ Trip Max-Speed (DIS 0x24 ×0.1)',             board:0x01,reg:0x24,len:2},
  {label:'⤓ Trip Ø-Speed (DIS 0x27 ×0.1)',               board:0x01,reg:0x27,len:2},
  {label:'⤓ Werks-/Rated-Cap, read-only (DIS 0x48 ×0.1)',board:0x01,reg:0x48,len:2},
  {label:'⤓ MCU Firmware-Cap (MCU 0x09)',                board:0x02,reg:0x09,len:2},
  {label:'⤓ Speed-Limit / User-Lock (DIS 0x93)',         board:0x01,reg:0x93,len:2},
  {label:'⤓ SpeedSafeLock (MCU 0x53)',                   board:0x02,reg:0x53,len:2},
  {label:'⤓ Gear-TopSpeed M1 (MCU 0x31)',                board:0x02,reg:0x31,len:2},
  {label:'⤓ Gear-TopSpeed M2 (MCU 0x49)',                board:0x02,reg:0x49,len:2},
  {label:'⤓ Gear-Profil-1 roh, 32B (MCU 0x22)',          board:0x02,reg:0x22,len:32},
  {label:'⤓ Modus-Bitmaske (DIS 0xAA)',                  board:0x01,reg:0xAA,len:2},
  {label:'⤓ KERS / Energie (MCU 0x2C)',                  board:0x02,reg:0x2C,len:2},
  {label:'⤓ Beschleunigung (MCU 0x2D)',                  board:0x02,reg:0x2D,len:2},
  {label:'⤓ Nitro / Boost (MCU 0x30)',                   board:0x02,reg:0x30,len:2},
  // reads - telemetry / status
  {label:'⤓ Akku % (DIS 0xB5)',                          board:0x01,reg:0xB5,len:2},
  {label:'⤓ Leistung W, signed (DIS 0xBD)',              board:0x01,reg:0xBD,len:2},
  {label:'⤓ Gesamt-km (DIS 0xB7 ×0.001)',                board:0x01,reg:0xB7,len:4},
  {label:'⤓ Trip-km (DIS 0xB9)',                         board:0x01,reg:0xB9,len:4},
  {label:'⤓ Reichweite (DIS 0x25 ×0.1)',                 board:0x01,reg:0x25,len:2},
  {label:'⤓ Trip-Laufzeit s (DIS 0xBA)',                 board:0x01,reg:0xBA,len:2},
  {label:'⤓ Status-Flags (DIS 0xB2: 2881=an/2882=aus)',  board:0x01,reg:0xB2,len:2},
  {label:'⤓ FunBool-Schalter (DIS 0x7D)',                board:0x01,reg:0x7D,len:2},
  {label:'⤓ CTLBool2-Schalter (DIS 0x7C)',               board:0x01,reg:0x7C,len:2},
  {label:'⤓ Serien-Nr (DIS 0x10)',                       board:0x01,reg:0x10,len:14},
  {label:'⤓ Dashboard-FW (DIS 0x1A)',                    board:0x01,reg:0x1A,len:2},
  {label:'⤓ BLE-FW (BLE 0x68)',                          board:0x04,reg:0x68,len:2},
  {label:'⤓ BMS Spannung (BMS1 0x1A ×0.01V)',            board:0x07,reg:0x1A,len:2},
  {label:'⤓ BMS Ladestand (BMS1 0x32 %)',                board:0x07,reg:0x32,len:2},
  {label:'⤓ BMS Zyklen (BMS1 0x1B)',                     board:0x07,reg:0x1B,len:2},
  {label:'⤓ BMS Restkapazität (BMS1 0x26)',              board:0x07,reg:0x26,len:2},
  // writes - speed levers (examples; whole km/h unless noted)
  {label:'✎ Speed-Limit AUS (DIS 0x93)',                 board:0x01,reg:0x93,len:2,val:'00 00'},
  {label:'✎ Speed-Limit → 20 km/h (DIS 0x93)',           board:0x01,reg:0x93,len:2,val:'14 00'},
  {label:'✎ Speed-Limit → 25 km/h (DIS 0x93)',           board:0x01,reg:0x93,len:2,val:'19 00'},
  {label:'✎ Speed-Limit → 45 km/h (DIS 0x93)',           board:0x01,reg:0x93,len:2,val:'2d 00'},
  {label:'✎ Speed-Limit → 60 km/h (DIS 0x93)',           board:0x01,reg:0x93,len:2,val:'3c 00'},
  {label:'✎ Gear-TopSpeed M1 → 25 km/h (MCU 0x31)',      board:0x02,reg:0x31,len:2,val:'19 00'},
  {label:'✎ Gear-TopSpeed M1 → 40 km/h (MCU 0x31)',      board:0x02,reg:0x31,len:2,val:'28 00'},
  {label:'✎ SpeedSafeLock → 25 km/h (MCU 0x53)',         board:0x02,reg:0x53,len:2,val:'19 00'},
  {label:'✎ Beschleunigung max (MCU 0x2D)',              board:0x02,reg:0x2D,len:2,val:'64 00'},
  {label:'✎ Nitro/Boost AN (MCU 0x30)',                  board:0x02,reg:0x30,len:2,val:'01 00'},
  {label:'✎ Nitro/Boost AUS (MCU 0x30)',                 board:0x02,reg:0x30,len:2,val:'00 00'},
  {label:'✎ KERS 20% (MCU 0x2C)',                        board:0x02,reg:0x2C,len:2,val:'14 00'},
  {label:'✎ KERS 100% (MCU 0x2C)',                       board:0x02,reg:0x2C,len:2,val:'64 00'},
  {label:'✎ Modus Eco (DIS 0xAA)',                       board:0x01,reg:0xAA,len:2,val:'01 00'},
  {label:'✎ Modus Drive (DIS 0xAA)',                     board:0x01,reg:0xAA,len:2,val:'02 00'},
  {label:'✎ Modus Sport (DIS 0xAA)',                     board:0x01,reg:0xAA,len:2,val:'04 00'},
];
// kick / M365-ES-Max family (CamiAlfa m365_register_map.h + etransport ES2ESC/ES2BMS + py9b).
const KICK_PRESETS=[
  // reads - speed & status
  {label:'⤓ Geschwindigkeit (ESC 0xB5 ×0.1)',           board:0x20,reg:0xB5,len:2},
  {label:'⤓ Ø-Speed (ESC 0xB6 ×0.1)',                   board:0x20,reg:0xB6,len:2},
  {label:'⤓ Akku % (ESC 0xB4)',                         board:0x20,reg:0xB4,len:2},
  {label:'⤓ Aktuelles Speed-Limit (ESC 0xBC ×0.1)',     board:0x20,reg:0xBC,len:2},
  {label:'⤓ Leistung W (ESC 0xBD)',                     board:0x20,reg:0xBD,len:2},
  {label:'⤓ Rahmen-Temp (ESC 0x3E ×0.1°C)',             board:0x20,reg:0x3E,len:2},
  {label:'⤓ Modus-Anzeige (ESC 0x1F: 0=Drive/1=Eco/2=Sport)', board:0x20,reg:0x1F,len:2},
  {label:'⤓ Gesamt-km (ESC 0xB7, 4B Meter)',            board:0x20,reg:0xB7,len:4},
  {label:'⤓ Trip-km (ESC 0xB9 ×0.01)',                  board:0x20,reg:0xB9,len:2},
  {label:'⤓ ESC-Firmware (ESC 0x1A)',                   board:0x20,reg:0x1A,len:2},
  {label:'⤓ Fehlercode (ESC 0x1B)',                     board:0x20,reg:0x1B,len:2},
  {label:'⤓ Serien-Nr (ESC 0x10, Region=4. Zeichen)',   board:0x20,reg:0x10,len:14},
  // reads - BMS (0x22)
  {label:'⤓ BMS-Block (0x22 0x31, 10B: cap/soc/strom/volt/temp)', board:0x22,reg:0x31,len:10},
  {label:'⤓ BMS Ladestand (0x22 0x32 %)',               board:0x22,reg:0x32,len:2},
  {label:'⤓ BMS Strom (0x22 0x33 s16 ×0.01A)',          board:0x22,reg:0x33,len:2},
  {label:'⤓ BMS Spannung (0x22 0x34 ×0.01V)',           board:0x22,reg:0x34,len:2},
  {label:'⤓ BMS Temperaturen (0x22 0x35, je −20°C)',    board:0x22,reg:0x35,len:2},
  {label:'⤓ BMS Gesundheit SoH (0x22 0x3B %)',          board:0x22,reg:0x3B,len:2},
  {label:'⤓ BMS Zellspannungen (0x22 0x40, 20B)',       board:0x22,reg:0x40,len:20},
  // writes - speed levers
  {label:'✎ Speed-Limiter AN (ESC 0x72)',               board:0x20,reg:0x72,len:2,val:'01 00'},
  {label:'✎ Speed-Limiter AUS (ESC 0x72)',              board:0x20,reg:0x72,len:2,val:'00 00'},
  {label:'✎ Drive-Limit → 20 km/h (ESC 0x73 LE×10)',    board:0x20,reg:0x73,len:2,val:'c8 00'},
  {label:'✎ Drive-Limit → 25 km/h (ESC 0x73 LE×10)',    board:0x20,reg:0x73,len:2,val:'fa 00'},
  {label:'✎ Eco-Limit → 20 km/h (ESC 0x74 LE×10)',      board:0x20,reg:0x74,len:2,val:'c8 00'},
  {label:'✎ ALT-Kandidat: 0x72 BE×10 = 30 km/h (umstritten)', board:0x20,reg:0x72,len:2,val:'01 2c'},
  {label:'✎ Modus Normal/Drive (ESC 0x75)',             board:0x20,reg:0x75,len:2,val:'00 00'},
  {label:'✎ Modus Eco (ESC 0x75)',                      board:0x20,reg:0x75,len:2,val:'01 00'},
  {label:'✎ Modus Sport (ESC 0x75)',                    board:0x20,reg:0x75,len:2,val:'02 00'},
  {label:'✎ KERS schwach (ESC 0x7B)',                   board:0x20,reg:0x7B,len:2,val:'00 00'},
  {label:'✎ KERS mittel (ESC 0x7B)',                    board:0x20,reg:0x7B,len:2,val:'01 00'},
  {label:'✎ KERS stark (ESC 0x7B)',                     board:0x20,reg:0x7B,len:2,val:'02 00'},
  {label:'✎ Cruise AN (ESC 0x7C)',                      board:0x20,reg:0x7C,len:2,val:'01 00'},
  {label:'✎ Cruise AUS (ESC 0x7C)',                     board:0x20,reg:0x7C,len:2,val:'00 00'},
  {label:'✎ Rücklicht AN (ESC 0x7D)',                   board:0x20,reg:0x7D,len:2,val:'02 00'},
  {label:'✎ Rücklicht AUS (ESC 0x7D)',                  board:0x20,reg:0x7D,len:2,val:'00 00'},
  {label:'✎ Sperren/Lock (ESC 0x70 - Roller rebootet)', board:0x20,reg:0x70,len:2,val:'01 00'},
  {label:'✎ Entsperren/Unlock (ESC 0x71 - Roller rebootet)', board:0x20,reg:0x71,len:2,val:'01 00'},
];
// VCU family (GT3/ZT3/Max G3/F3) - board 0x16 + TFT 0x23. Values unverified; whole km/h assumed.
const VCU_PRESETS=[
  {label:'⤓ Speed-Cap lesen (VCU 0x46)',                 board:0x16,reg:0x46,len:2},
  {label:'✎ Speed-Cap → 20 km/h (VCU 0x46)',             board:0x16,reg:0x46,len:2,val:'14 00'},
  {label:'✎ Speed-Cap → 25 km/h (VCU 0x46)',             board:0x16,reg:0x46,len:2,val:'19 00'},
  {label:'⤓ Modus (VCU 0x5A)',                           board:0x16,reg:0x5A,len:2},
  {label:'⤓ KERS/Rekuperation (VCU 0x70)',               board:0x16,reg:0x70,len:2},
  {label:'⤓ Rücklicht (VCU 0x5D)',                       board:0x16,reg:0x5D,len:2},
  {label:'✎ Rücklicht AN (VCU 0x5D)',                    board:0x16,reg:0x5D,len:2,val:'02 00'},
  {label:'⤓ Serien-Nr (VCU 0x10)',                       board:0x16,reg:0x10,len:14},
  {label:'⤓ TFT-Dashboard probe (0x23 0x10)',            board:0x23,reg:0x10,len:14},
];
let RAW_PRESETS=[...MODERN_PRESETS,...VCU_PRESETS,...KICK_PRESETS];

// ---- helpers ----
function concat(...a){ const t=a.reduce((s,x)=>s+x.length,0),r=new Uint8Array(t); let o=0; for(const x of a){r.set(x,o);o+=x.length;} return r; }
function xor16(a,b){ const r=new Uint8Array(16); for(let i=0;i<16;i++) r[i]=(a[i]||0)^(b[i]||0); return r; }
function pad16(d){ const r=new Uint8Array(16); r.set(d.slice(0,16)); return r; }
function hex(b){ return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join(''); }
function u16le(d,o=0){ return d[o]|(d[o+1]<<8); }
function i16le(d,o=0){ const v=u16le(d,o); return v>=0x8000?v-0x10000:v; }
function u32le(d,o=0){ return (d[o]|(d[o+1]<<8)|(d[o+2]<<16)|(d[o+3]<<24))>>>0; }
async function sha1(d){ return new Uint8Array(await crypto.subtle.digest('SHA-1',d)); }
function sleep(ms){ return new Promise(r=>setTimeout(r,ms)); }

// ---- AES: WebCrypto has no raw ECB → emulate via AES-CBC(iv=0) on one block ----
async function importKey(raw){ return crypto.subtle.importKey('raw',raw,{name:'AES-CBC'},false,['encrypt']); }
async function aesEcb(ck,b16){ const e=new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC',iv:new Uint8Array(16)},ck,b16)); return e.slice(0,16); }
async function setSessionKey(raw){ sessionKey=await importKey(raw); }
async function deriveKey(k1,k2){ return (await sha1(concat(pad16(k1),pad16(k2||new Uint8Array(16))))).slice(0,16); }
function buildNonce(ctr,ap){ const n=new Uint8Array(13); n[0]=(ctr>>>24)&0xFF;n[1]=(ctr>>>16)&0xFF;n[2]=(ctr>>>8)&0xFF;n[3]=ctr&0xFF; if(ap)n.set(ap.slice(0,8),4); return n; }

// ---- Encryption2 SN ----  inner=[3E,target,cmd,index,...data] (4+N); header=[5A,sync2,N]
async function cbcMac(ck,nonce,header,inner){
  const b0=new Uint8Array(16); b0[0]=0x59; b0.set(nonce,1); b0[15]=inner.length&0xFF;
  let x=await aesEcb(ck,b0);
  x=await aesEcb(ck,xor16(x,pad16(header)));                 // AAD over header [OK]
  for(let i=0;i<inner.length;i+=16) x=await aesEcb(ck,xor16(x,pad16(inner.slice(i,i+16))));
  return x.slice(0,4);
}
async function ctrXor(ck,nonce,data,start){
  const out=new Uint8Array(data.length);
  for(let j=0;j*16<data.length;j++){ const a=new Uint8Array(16); a[0]=0x01; a.set(nonce,1); a[15]=(start+j)&0xFF;
    const ks=await aesEcb(ck,a); for(let k=0;k<16&&j*16+k<data.length;k++) out[j*16+k]=data[j*16+k]^ks[k]; }
  return out;
}
async function encryptSN(ck,ctr,ap,inner){
  const N=inner.length-4, header=new Uint8Array([0x5A,proto.sync2,N&0xFF]), nonce=buildNonce(ctr,ap);
  const tag=await cbcMac(ck,nonce,header,inner);
  const s0=await aesEcb(ck,new Uint8Array([0x01,...nonce,0x00,0x00])); const encTag=new Uint8Array(4); for(let i=0;i<4;i++) encTag[i]=tag[i]^s0[i];
  const cipher=await ctrXor(ck,nonce,inner,1);
  return concat(header,cipher,encTag,new Uint8Array([(ctr>>8)&0xFF,ctr&0xFF]));
}
async function encryptNonSN(ck,inner){ // PRE_COMM, counter 0 [OK]
  const N=inner.length-4, header=new Uint8Array([0x5A,proto.sync2,N&0xFF]);
  const ks=await aesEcb(ck,proto.ecb), cipher=new Uint8Array(inner.length);
  for(let i=0;i<inner.length;i++) cipher[i]=inner[i]^ks[i%16];
  let s=0; for(const b of inner) s+=b; const cs=(~s)&0xFFFF;
  return concat(header,cipher,new Uint8Array([0,0,cs&0xFF,(cs>>8)&0xFF,0,0]));
}
async function decryptFrame(ck,frame,ap){
  const N=frame[2], cipher=frame.slice(3,3+4+N), ctr=(frame[frame.length-2]<<8)|frame[frame.length-1];
  if(ctr===0){ const ks=await aesEcb(ck,proto.ecb),inner=new Uint8Array(cipher.length); for(let i=0;i<cipher.length;i++) inner[i]=cipher[i]^ks[i%16]; return inner; }
  return ctrXor(ck,buildNonce(ctr,ap),cipher,1);
}

// ---- Legacy Protocol-2 (plaintext) ----  CRC=(~sum(bytes[2..end-2]))&0xFFFF, LO first [OK]
function buildP2(target,cmd,reg,data){
  const p=data||new Uint8Array(0), f=new Uint8Array(9+p.length);
  f[0]=0x5A;f[1]=0xA5;f[2]=p.length;f[3]=0x3E;f[4]=target;f[5]=cmd;f[6]=reg; f.set(p,7);
  let s=0; for(let i=2;i<f.length-2;i++) s=(s+f[i])&0xFFFF; const cs=(~s)&0xFFFF; f[f.length-2]=cs&0xFF; f[f.length-1]=(cs>>8)&0xFF;
  return f;
}
function parseP2(f){ if(f.length<9||f[0]!==0x5A) return null; const len=f[2]; return {src:f[3],dst:f[4],cmd:f[5],reg:f[6],data:f.slice(7,7+len)}; }

// ---- send ----
async function sendRead(target,reg,nbytes){
  if(encrypted){ counter++; await writeChar.writeValue(await encryptSN(sessionKey,counter,authParam,new Uint8Array([0x3E,target,CMD.READ,reg,nbytes]))); }
  else await writeChar.writeValue(buildP2(target,CMD.READ,reg,new Uint8Array([nbytes])));
}
async function sendWrite(target,reg,data){
  if(encrypted){ counter++; await writeChar.writeValue(await encryptSN(sessionKey,counter,authParam,concat(new Uint8Array([0x3E,target,CMD.WRITE,reg]),data))); }
  else await writeChar.writeValue(buildP2(target,CMD.WRITE,reg,data));
}
async function sendCommand(target,cmd,index,payload){ // 0x63 unlock braucht 16-Byte-Ident; 0x57 activate = cloud/konto-gebunden, Payload nirgends öffentlich (auch nicht in der App-Binary) - nicht nachbaubar
  const inner=concat(new Uint8Array([0x3E,target,cmd,index]),payload||new Uint8Array(0));
  if(encrypted){ counter++; await writeChar.writeValue(await encryptSN(sessionKey,counter,authParam,inner)); }
  else await writeChar.writeValue(buildP2(target,cmd,index,payload||new Uint8Array(0)));
}

// ---- settings ----
function encodeSetting(def,idx,raw){
  switch(def.enc){
    case 'u16le_whole':{ const v=Math.round(raw); return new Uint8Array([v&0xFF,(v>>8)&0xFF]); }
    case 'u16be_x10':{ const v=Math.round(raw*10); return new Uint8Array([(v>>8)&0xFF,v&0xFF]); }
    case 'u16le_x10':{ const v=Math.round(raw*10); return new Uint8Array([v&0xFF,(v>>8)&0xFF]); }
    case 'u16le_map':{ const v=def.map[idx]; return new Uint8Array([v&0xFF,(v>>8)&0xFF]); }
    case 'u16le_low': return new Uint8Array([raw&0xFF,0]);
    case 'u8': return new Uint8Array([(def.map?def.map[idx]:idx)&0xFF]);
    case 'u8_02': return new Uint8Array([idx?2:0]);
  }
  return new Uint8Array(0);
}
async function applySetting(name,idx,raw){
  const def=scheme.settings[name];
  if(!def){ log(name+': '+(t('naScheme')||'für dieses Schema nicht dokumentiert')); return; }
  try{ if(def.pre) await sendWrite(def.t,def.pre.reg,new Uint8Array(def.pre.data)); await sendWrite(def.t,def.reg,encodeSetting(def,idx,raw)); log(name+' → '+(raw!==undefined?raw:idx)+(def.conf==='?'?' ['+( t('unverified')||'unbestätigt')+']':'')); }
  catch(e){ log(name+' Fehler: '+e.message); }
}
const setSpeed=kmh=>applySetting('speed',0,kmh);
const setMode=i=>applySetting('mode',i);
const setKERS=i=>applySetting('kers',i);
const setCruise=on=>applySetting('cruise',on?1:0);
const setTailLight=on=>applySetting('taillight',on?1:0);
const setVolume=v=>applySetting('volume',0,v);

// ---- speed-limit switch (token-free) ----
async function setSpeedLimitOff(){
  const off=scheme.settings.speedOff; if(!off){ log('speedOff n/a'); return; }
  try{ await sendWrite(off.t,off.reg,new Uint8Array(off.data)); log(t('slOffDone')||'Limit aus (offen)'); }
  catch(e){ log('Fehler: '+e.message); }
}

// ---- serial-number backup / restore / region (writes cmd 0x18) ----
function downloadJSON(name,obj){
  try{ const blob=new Blob([JSON.stringify(obj,null,2)],{type:'application/json'}); const url=URL.createObjectURL(blob);
    const a=document.createElement('a'); a.href=url; a.download=name; document.body.appendChild(a); a.click();
    setTimeout(()=>{ URL.revokeObjectURL(url); a.remove(); },1000);
  }catch(e){ log('Download: '+e.message); }
}
function currentSnapshot(){ return { tool:'sw-unlock', build:BUILD, ts:new Date().toISOString(), bleName,
  model:currentModel&&currentModel.name, profile:currentModel&&currentModel.p, gen:(encrypted?(proto.sync2===0xA5?'gen2':'gen3'):'legacy'),
  serial:INFO.serial||null, fwVer:INFO.fwVer||null, telemetry:{...INFO} }; }
function lastBackup(){ try{ return (JSON.parse(localStorage.getItem('segway_sn_backup')||'[]'))[0]||null; }catch(e){ return null; } }
function renderBackupInfo(){
  const b=lastBackup(), el=document.getElementById('sn-backup-info');
  if(el) el.textContent=b?((t('snLast')||'Letzte Sicherung:')+' '+(b.serial||'?')+' · '+b.ts):'';
  const r=document.getElementById('sn-restore'), ack=document.getElementById('sn-ack');
  if(r) r.disabled=!(connected&&authDone&&scheme.serialWrite&&ack&&ack.checked&&b&&b.serial);
}
function doBackup(){ const snap=currentSnapshot();
  try{ const arr=JSON.parse(localStorage.getItem('segway_sn_backup')||'[]'); arr.unshift(snap); while(arr.length>20) arr.pop(); localStorage.setItem('segway_sn_backup',JSON.stringify(arr)); }catch(e){}
  downloadJSON('segway-backup-'+(INFO.serial||bleName||'device')+'-'+Date.now()+'.json',snap); renderBackupInfo();
  log(t('snBackupDone')||'Gesichert (Download + lokal).');
}
async function writeSerial(sn){ sn=(sn||'').trim();
  if(!scheme.serialWrite){ log(t('snNoWrite')||'SN-Schreiben für dieses Modell nicht möglich.'); return; }
  if(sn.length<8||sn.length>16){ log(t('snBadLen')||'SN-Länge unplausibel.'); return; }
  const sdef=scheme.tele.find(x=>x.key==='serial'), board=scheme.serialBoard||(sdef?sdef.t:0x01), reg=sdef?sdef.reg:0x10;
  if(!window.confirm((t('snConfirm1')||'SN überschreiben?')+'\n'+sn)) return;
  if(!window.confirm(t('snConfirm2')||'Letzte Warnung. Fortfahren?')) return;
  try{ await sendCommand(board,CMD.WRITE_SN,reg,new TextEncoder().encode(sn)); log('SN → '+sn+' · '+(t('snAfterWrite')||'')); }
  catch(e){ log('SN-Fehler: '+e.message); }
}
function restoreSn(){ const b=lastBackup(); if(!b||!b.serial){ log(t('snNoBackup')||'Keine Sicherung.'); return; }
  const i=document.getElementById('sn-new'); if(i) i.value=b.serial; writeSerial(b.serial);
}
function renderSn(){ set('sn-current',INFO.serial);
  const el=document.getElementById('sn-region'); if(el) el.textContent=(INFO.serial&&INFO.serial.length>=4)?('„'+INFO.serial[3]+'" '+(t('snRegionNote')||'')):'-';
  const bk=document.getElementById('sn-backup'); if(bk) bk.disabled=!(connected&&authDone&&INFO.serial);
  const note=document.getElementById('sn-note'); if(note) note.textContent=scheme.serialWrite?'':(t('snNoWrite')||'');
  renderBackupInfo();
}

// ---- auth ---- PRE_COMM non-SN(0) → start_sn(1) → SET_PWD(2) → AUTH(3) [OK]
async function authPhase1(){ await setSessionKey(await deriveKey(new TextEncoder().encode(bleName),new Uint8Array(16)));
  log('PRE_COMM → BLE'); await writeChar.writeValue(await encryptNonSN(sessionKey,new Uint8Array([0x3E,AUTH_TARGET,CMD.PRE_COMM,0x00]))); }
async function authPhase2(){ await setSessionKey(await deriveKey(new TextEncoder().encode(bleName),authParam)); counter=1; counter++;
  log('SET_PWD → BLE'); await writeChar.writeValue(await encryptSN(sessionKey,counter,authParam,concat(new Uint8Array([0x3E,AUTH_TARGET,CMD.SET_PWD,0x00]),password))); }
async function authPhase3(){ await setSessionKey(await deriveKey(password,authParam)); counter++;
  log('AUTH → BLE'); await writeChar.writeValue(await encryptSN(sessionKey,counter,authParam,concat(new Uint8Array([0x3E,AUTH_TARGET,CMD.AUTH,0x00]),serial))); }
async function doAuth(){ if(!encrypted){ authDone=true; afterAuth(); return; } log('Auth-Handshake…'); await authPhase1(); }
function afterAuth(){ setStatus('connected'); buildReadMap(); setTimeout(()=>{ readAll(); startPolling(); },400); }

async function handleResponse(p){
  switch(p.cmd){
    case CMD.PRE_COMM: if(p.data.length>=30){ authParam=p.data.slice(0,16); serial=p.data.slice(16,30);
        INFO.serial=new TextDecoder().decode(serial).replace(/\0/g,''); render();
        const rnd=new Uint8Array(16); crypto.getRandomValues(rnd); password=rnd; await authPhase2(); } break;
    case CMD.SET_PWD: if(p.reg===1||p.data[0]===1){ log('Passwort akzeptiert'); await authPhase3(); } else { log('Einschalttaste am Roller drücken…'); setTimeout(()=>authPhase3().catch(e=>log('Auth '+e.message)),2000); } break;
    case CMD.AUTH: if(p.reg===1||p.data[0]===1){ authDone=true; log('Auth OK'); afterAuth(); } else log('Auth fehlgeschlagen'); break;
    case CMD.READ_RESP: decodeRead(p.src,p.reg,p.data); break;
    case CMD.WRITE_RESP: log(p.data.length===0||p.data[0]===0?'Write OK':'Write abgelehnt ('+p.data[0]+')'); break;
  }
}

function buildReadMap(){ readMap=new Map(); for(const d of scheme.tele) readMap.set(d.t*256+d.reg,d); }
function decodeVal(def,d){
  switch(def.type){
    case 'ascii': return new TextDecoder().decode(d).replace(/\0/g,'').trim();
    case 'ver': { const v=u16le(d); return ((v>>8)&0xF)+'.'+((v>>4)&0xF)+'.'+(v&0xF); }
    case 'u16le': return u16le(d)*(def.scale||1);
    case 'u32le': return u32le(d)*(def.scale||1);
    case 'modebits': { const v=u16le(d); return (v&0x04)?2:(v&0x02)?1:(v&0x01)?0:undefined; }
    default: return hex(d);
  }
}
function decodeRead(src,reg,d){
  const rk=src*256+reg; if(rawWatch.has(rk)){ rawWatch.delete(rk); rawShow(src,reg,d); }
  if(scheme.bmsLegacy && src===scheme.bms[0]){
    if(reg===BMS_LEG_BLOCK.reg && d.length>=10){ const b=BMS[0]; b.restCap=u16le(d,0);b.soc=u16le(d,2);b.current=i16le(d,4)/100;b.voltage=u16le(d,6)/100;b.temp1=d[8]-20;b.temp2=d[9]-20; renderBms(); return; }
    if(reg===BMS_LEG_CELLS.reg){ const b=BMS[0]; b.cells=[]; for(let i=0;i+1<d.length;i+=2) b.cells.push(u16le(d,i)); renderBms(); return; }
  }
  if(!scheme.bmsLegacy){ const pi=scheme.bms.indexOf(src); if(pi>=0){ const r=BMS_E2.find(x=>x.reg===reg); if(r){ BMS[pi][r.field]=u16le(d)*(r.scale||1); renderBms(); return; } } }
  const def=readMap.get(src*256+reg); if(def){ INFO[def.key]=decodeVal(def,d); render(); }
}

// ---- read orchestration ----
async function readAll(){ for(const d of scheme.tele){ try{ await sendRead(d.t,d.reg,d.len); }catch(e){} await sleep(60); } await readBms(); }
async function readBms(){
  try{
    if(scheme.bmsLegacy){ await sendRead(scheme.bms[0],BMS_LEG_BLOCK.reg,BMS_LEG_BLOCK.len); await sleep(60); await sendRead(scheme.bms[0],BMS_LEG_CELLS.reg,BMS_LEG_CELLS.len); await sleep(60); }
    else for(const b of scheme.bms){ for(const r of BMS_E2){ try{ await sendRead(b,r.reg,r.len); }catch(e){} await sleep(50); } }
  }catch(e){}
}
function startPolling(){ stopPolling(); pollTimer=setInterval(async()=>{ if(!connected||!authDone) return;
  for(const d of scheme.tele.filter(x=>x.poll)){ try{ await sendRead(d.t,d.reg,d.len); }catch(e){} await sleep(50); } },1500); }
function stopPolling(){ if(pollTimer){ clearInterval(pollTimer); pollTimer=null; } }

// ---- Log + redaction (canonical fleet shell) ----
// Lines are kept raw in logBuffer so re-render, copy and save use the same anonymized text.
const logBuffer=[];            // { raw, cls }
let publicLog=true;            // anonymize before display/copy/save (default on)
let diagLog=false;             // verbose: keep every raw frame
let deviceId='';               // current device id, redacted from a public log
let deviceName='';             // current device name
try{ publicLog=localStorage.getItem('segway_publiclog')!=='0'; }catch(e){}
try{ diagLog=localStorage.getItem('segway_diaglog')==='1'; }catch(e){}
// Mask personal data before a log is shown or shared: the device id, MAC addresses, key/token/serial
// assignments, and long contiguous hex runs (space-separated frame hex stays readable).
function redact(text){
  let s=String(text);
  if(deviceId) s=s.split(deviceId).join('[redacted-id]');
  s=s.replace(/\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,'[redacted-mac]');
  s=s.replace(/\b(secret|token|key|aes|pwd|password|pin|mac|serial|sn|vin|uid|imei)\b(\s*[:=]\s*)("?)([^\s",]+)\3/gi,(m,k,sep)=>k+sep+'[redacted]');
  s=s.replace(/\b[0-9A-Fa-f]{16,}\b/g,'[redacted-hex]');
  return s;
}
function anonymize(s){
  if(publicLog===false) return String(s).replace(/\x01/g,'');
  return redact(String(s).replace(/\x01[^\x01]*\x01/g,'XX').replace(/\x01/g,''));
}
function log(msg,cls){
  console.log('[segway]',msg);
  const raw='['+new Date().toTimeString().slice(0,8)+'] '+msg;
  logBuffer.push({raw:raw,cls:cls||''});
  const el=document.getElementById('log');
  if(el){ const span=document.createElement('span'); if(cls) span.className=cls; span.textContent=anonymize(raw)+'\n'; el.appendChild(span); el.scrollTop=el.scrollHeight; }
  const ci=document.getElementById('conn-info'); if(ci) ci.textContent=msg;
}
function renderLog(){
  const el=document.getElementById('log'); if(!el) return; el.textContent='';
  logBuffer.forEach(e=>{ const span=document.createElement('span'); if(e.cls) span.className=e.cls; span.textContent=anonymize(e.raw)+'\n'; el.appendChild(span); });
  el.scrollTop=el.scrollHeight;
}
function clearLog(){ logBuffer.length=0; const el=document.getElementById('log'); if(el) el.textContent=''; log(t('logCleared')||'Log cleared.'); }
function copyLog(){
  const text=logBuffer.map(e=>anonymize(e.raw)).join('\n');
  if(navigator.clipboard&&navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(()=>log(t('logCopied')||'copied','log-ok')).catch(()=>copyLogFallback(text));
  else copyLogFallback(text);
}
function copyLogFallback(text){
  const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select();
  try{ document.execCommand('copy'); log(t('logCopied')||'copied','log-ok'); }catch(e){ log('copy failed: '+e,'log-err'); } document.body.removeChild(ta);
}
function saveLog(){
  const text=logBuffer.map(e=>anonymize(e.raw)).join('\n');
  try{ const blob=new Blob([text],{type:'text/plain'}); const url=URL.createObjectURL(blob); const a=document.createElement('a'); a.href=url; a.download='segway-log.txt'; document.body.appendChild(a); a.click(); document.body.removeChild(a); setTimeout(()=>URL.revokeObjectURL(url),1000); log(t('logSaved')||'saved','log-ok'); }
  catch(e){ log('save failed: '+e,'log-err'); }
}
// Canonical hidden-until-connect: content cards appear on connect, hide on disconnect/load.
function revealCards(on){
  ['speedlimit-card','settings-card','live-card','sn-card','raw-card'].forEach(id=>{ const el=document.getElementById(id); if(el) el.hidden=!on; });
  if(!on){ const b=document.getElementById('bms-card'); if(b) b.hidden=true; }
}

// ---- BLE ----
function setStatus(state){
  const el=document.getElementById('status'); if(el){ el.setAttribute('data-state',state); el.textContent=t('status_'+state)||state; }
  connected=(state==='connected');
  revealCards(connected);
  const btn=document.getElementById('btn-conn'); if(btn){ btn.textContent=connected?t('btnDisconnect'):t('btnConnect'); btn.disabled=false; }
  refreshControls();
}
function refreshControls(){
  const ok=connected&&authDone;
  for(const n of ['speed','mode','kers','cruise','taillight','volume']){
    const avail=ok && !!scheme.settings[n];
    for(const id of [n+'-in','btn-set-'+n]){ const e=document.getElementById(id); if(e){ e.disabled=!avail; if(!scheme.settings[n]) e.title=t('naScheme')||''; else e.title=''; } }
  }
  for(const id of ['raw-read','raw-write']){ const e=document.getElementById(id); if(e) e.disabled=!ok; }
  const hasSpeed=!!scheme.settings.speed, hasOff=!!scheme.settings.speedOff;
  for(const id of ['sl-kmh','sl-on']){ const e=document.getElementById(id); if(e) e.disabled=!(ok&&hasSpeed); }
  const slOff=document.getElementById('sl-off'); if(slOff) slOff.disabled=!(ok&&hasOff);
  const slNote=document.getElementById('sl-note');
  if(slNote) slNote.textContent=!hasSpeed?(t('slNoSpeed')||''):(!hasOff?(t('slNoOff')||''):'');
  const ack=document.getElementById('sn-ack'), snOk=ok&&scheme.serialWrite&&ack&&ack.checked;
  for(const id of ['sn-new','sn-write']){ const e=document.getElementById(id); if(e) e.disabled=!snOk; }
  const bk=document.getElementById('sn-backup'); if(bk) bk.disabled=!(ok && INFO.serial);
  renderBackupInfo();
}
// pick a model → set profile + board/registers + default gen, refresh UI
function applyModel(idx){
  const m=MODELS[idx]; if(!m) return; currentModel=m; scheme=PROFILES[m.p]||PROFILES.eseries;
  const g=scheme.gen||'gen3'; encrypted=(g!=='legacy'); proto=(g==='gen2')?GEN.gen2:GEN.gen3;
  const gs=document.getElementById('gen-sel'); if(gs) gs.value=g;
  try{ localStorage.setItem('segway_model',String(idx)); }catch(e){}
  buildReadMap(); refreshControls(); render();
  log((t('modelSet')||'Modell:')+' '+m.name);
}
function initModels(){
  const sel=document.getElementById('model-sel'); if(!sel) return; sel.textContent=''; let i=0;
  for(const g of MODEL_GROUPS){ const og=document.createElement('optgroup'); og.label=t(g.gkey)||g.gkey;
    for(const m of g.models){ const o=document.createElement('option'); o.value=String(i); o.textContent=m.name; og.appendChild(o); i++; }
    sel.appendChild(og); }
  let saved; try{ saved=parseInt(localStorage.getItem('segway_model'),10); }catch(e){}
  if(!(saved>=0&&saved<MODELS.length)) saved=0; sel.value=String(saved); applyModel(saved);
}
async function detectService(server){
  for(const [uuid,type] of [[NINEBOT_SVC,'ninebot'],[NORDIC_SVC,'nordic'],[ISSC_SVC,'issc'],[HMSOFT_SVC,'hmsoft'],[FEE7_SVC,'fee7']]){ try{ svc=await server.getPrimaryService(uuid); return type; }catch(e){} }
  for(const uuid of VENDOR_16BIT){ try{ svc=await server.getPrimaryService(uuid); return 'vendor16'; }catch(e){} }
  throw new Error('Kein bekannter BLE-Service gefunden');
}
async function connect(){
  try{
    log('Suche…'); setStatus('scanning');
    device=await navigator.bluetooth.requestDevice({ filters:NAME_PREFIXES.map(p=>({namePrefix:p})), optionalServices:OPTIONAL_SERVICES });
    bleName=device.name||''; deviceName=bleName; deviceId=device.id||''; const bn=document.getElementById('t-blename'); if(bn) bn.textContent=bleName; log('Gefunden: '+bleName);
    device.addEventListener('gattserverdisconnected',onDisconnect);
    server=await device.gatt.connect();
    const svcType=await detectService(server); log('Service: '+svcType);
    writeChar=await svc.getCharacteristic(WRITE_UUIDS[svcType]);
    notifyChar=await svc.getCharacteristic(NOTIFY_UUIDS[svcType]);
    await notifyChar.startNotifications(); notifyChar.addEventListener('characteristicvaluechanged',onNotify);
    setStatus('connected'); counter=0; authDone=false; await doAuth();
  }catch(e){ log('Fehler: '+e.message); setStatus('disconnected'); }
}
async function disconnect(){ stopPolling(); try{ if(server) await server.disconnect(); }catch(e){}
  device=server=svc=writeChar=notifyChar=null; authDone=false; authParam=serial=sessionKey=password=null; counter=0; setStatus('disconnected'); log('Getrennt'); }
function onDisconnect(){ stopPolling(); setStatus('disconnected'); log('Verbindung getrennt'); }

let rxBuf=new Uint8Array(0);
async function onNotify(event){
  rxBuf=concat(rxBuf,new Uint8Array(event.target.value.buffer));
  while(rxBuf.length>=3){
    if(rxBuf[0]!==0x5A||(rxBuf[1]!==0xA5&&rxBuf[1]!==0xB5)){ rxBuf=rxBuf.slice(1); continue; }
    const total=encrypted?(rxBuf[2]+13):(rxBuf[2]+9);
    if(rxBuf.length<total) break;
    const frame=rxBuf.slice(0,total); rxBuf=rxBuf.slice(total);
    try{ let p; if(encrypted){ const inner=await decryptFrame(sessionKey,frame,authParam); if(inner&&inner.length>=4) p={src:inner[0],dst:inner[1],cmd:inner[2],reg:inner[3],data:inner.slice(4)}; } else p=parseP2(frame); if(p) await handleResponse(p); }catch(e){}
  }
}

// ---- render ----
function set(id,v){ const e=document.getElementById(id); if(e) e.textContent=(v===undefined||v===null||v==='')?'-':v; }
function render(){
  set('t-serial',INFO.serial); set('t-fwver',INFO.fwVer);
  set('t-speed',INFO.speed!==undefined?INFO.speed.toFixed(1):undefined);
  set('t-battery',INFO.battery!==undefined?INFO.battery+' %':undefined);
  set('t-speedlimit',INFO.speedLimit!==undefined?INFO.speedLimit+' km/h':undefined);
  set('t-mode',INFO.mode!==undefined?(['Eco','Drive','Sport'][INFO.mode]||INFO.mode):undefined);
  set('t-odo',INFO.odo!==undefined?INFO.odo.toFixed(2)+' km':undefined);
  set('t-trip',INFO.trip!==undefined?INFO.trip.toFixed(2)+' km':undefined);
  set('t-range',INFO.range!==undefined?INFO.range.toFixed(1)+' km':undefined);
  if(INFO.speedLimit!==undefined){ const i=document.getElementById('speed-in'); if(i&&!i.matches(':focus')) i.value=INFO.speedLimit; }
  if(INFO.mode!==undefined){ const i=document.getElementById('mode-in'); if(i) i.value=String(INFO.mode); }
  if(INFO.speedLimit!==undefined){ const i=document.getElementById('sl-kmh'); if(i&&!i.matches(':focus')&&!i.value) i.value=INFO.speedLimit; }
  renderSn();
}
function renderBms(){
  const card=document.getElementById('bms-card'); if(card) card.hidden=false;
  const b=BMS[0];
  set('b-soc',b.soc!==undefined?b.soc+' %':undefined);
  set('b-voltage',b.voltage!==undefined?(typeof b.voltage==='number'?b.voltage.toFixed(2):b.voltage)+' V':undefined);
  set('b-current',b.current!==undefined?b.current.toFixed(2)+' A':undefined);
  set('b-temp',b.temp1!==undefined?b.temp1+'/'+b.temp2+' °C':undefined);
  set('b-cycles',b.cycles);
  const cont=document.getElementById('b-cells'); if(cont){ cont.textContent=''; if(b.cells) b.cells.forEach((mv,i)=>{ const s=document.createElement('span'); s.className='cell'; s.textContent='Z'+(i+1)+': '+(mv/1000).toFixed(3)+'V'; cont.appendChild(s); }); }
  const note=document.getElementById('b-note'); if(note) note.textContent = scheme.bmsLegacy ? '' : (t('bmsNoteE2')||'');
}

// ---- Raw register console ----
function hex2(x){ return (x&0xFF).toString(16).padStart(2,'0'); }
function parseHex(s){ if(!s) return new Uint8Array(0); s=String(s).replace(/0x/gi,'').replace(/[^0-9a-fA-F]/g,''); if(s.length%2) s='0'+s; const a=new Uint8Array(s.length/2); for(let i=0;i<a.length;i++) a[i]=parseInt(s.substr(i*2,2),16); return a; }
function parseRegByte(s){ if(!s) return 0; s=String(s).trim().toLowerCase().replace(/^0x/,''); return (parseInt(s,16)||0)&0xFF; }
function rawLog(text){ const out=document.getElementById('raw-out'); if(!out) return; const div=document.createElement('div'); div.className='rl'; div.textContent=text; out.insertBefore(div,out.firstChild); while(out.children.length>16) out.removeChild(out.lastChild); }
function rawShow(src,reg,d){
  const parts=[];
  if(d.length>=1) parts.push('u8='+d[0]);
  if(d.length>=2) parts.push('u16le='+u16le(d)); if(d.length>=2) parts.push('u16be='+((d[0]<<8)|d[1]));
  if(d.length>=4) parts.push('u32le='+u32le(d));
  if(d.length) parts.push('ascii="'+new TextDecoder().decode(d).replace(/[^\x20-\x7e]/g,'·')+'"');
  rawLog('◀ 0x'+hex2(src)+'/0x'+hex2(reg)+' = '+(hex(d)||'∅')+'\n   '+parts.join('  '));
}
async function rawRead(){
  if(!connected||!authDone) return;
  const board=parseInt(document.getElementById('raw-board').value,10);
  const reg=parseRegByte(document.getElementById('raw-reg').value);
  let len=parseInt(document.getElementById('raw-len').value,10)||1; len=Math.max(1,Math.min(60,len));
  rawWatch.add(board*256+reg);
  rawLog('▶ READ 0x'+hex2(board)+'/0x'+hex2(reg)+' ×'+len);
  try{ await sendRead(board,reg,len); }catch(e){ rawLog('Fehler: '+e.message); }
}
async function rawWrite(){
  if(!connected||!authDone) return;
  const board=parseInt(document.getElementById('raw-board').value,10);
  const reg=parseRegByte(document.getElementById('raw-reg').value);
  const bytes=parseHex(document.getElementById('raw-val').value);
  if(!bytes.length){ rawLog(t('rawNoBytes')||'Keine Bytes.'); return; }
  const desc='0x'+hex2(board)+'/0x'+hex2(reg)+' = '+hex(bytes);
  if(!window.confirm((t('rawConfirm')||'Roh-Schreiben bestätigen?')+'\n'+desc)) return;
  rawLog('▶ WRITE '+desc);
  try{ await sendWrite(board,reg,bytes); }catch(e){ rawLog('Fehler: '+e.message); }
}
function initRaw(){
  const bsel=document.getElementById('raw-board');
  if(bsel){ const cur=bsel.value; bsel.textContent=''; for(const b of RAW_BOARDS){ const o=document.createElement('option'); o.value=String(b.v); o.textContent=b.n; bsel.appendChild(o);} if(cur) bsel.value=cur; }
  const psel=document.getElementById('raw-preset');
  if(psel){ psel.textContent=''; const o0=document.createElement('option'); o0.value=''; o0.textContent=t('rawPresetNone')||'- Vorlage -'; psel.appendChild(o0);
    RAW_PRESETS.forEach((p,i)=>{ const o=document.createElement('option'); o.value=String(i); o.textContent=p.label; psel.appendChild(o); }); }
}

// ---- Dialogs: doc viewer / help / confirm (canonical fleet shell) ----
function confirmDialog(bodyText){
  return new Promise(resolve=>{
    const dlg=document.getElementById('confirm'); if(!dlg){ resolve(window.confirm(bodyText)); return; }
    document.getElementById('confirm-body').textContent=bodyText;
    const ok=document.getElementById('confirm-ok'),cancel=document.getElementById('confirm-cancel'),cx=document.getElementById('confirm-cancel-x');
    const close=res=>{ cleanup(); if(dlg.close) dlg.close(); else dlg.removeAttribute('open'); resolve(res); };
    const okH=()=>close(true),caH=()=>close(false);
    function cleanup(){ ok.removeEventListener('click',okH); cancel.removeEventListener('click',caH); if(cx) cx.removeEventListener('click',caH); }
    ok.addEventListener('click',okH); cancel.addEventListener('click',caH); if(cx) cx.addEventListener('click',caH);
    if(dlg.showModal) dlg.showModal(); else dlg.setAttribute('open','');
  });
}
const HELP={
  raw:['rawTitle','rawHelp'],
  publiclog:['publicLogTitle','publicLogHelpHtml'],
  diaglog:['diagLogTitle','diagLogHelpHtml'],
};
function openHelp(key){
  const h=HELP[key]; if(!h) return;
  document.getElementById('help-title').textContent=t(h[0]);
  const body=document.getElementById('help-body'); const s=t(h[1])||'';
  body.innerHTML=/Html$/.test(h[1])?s:mdToHtml(s); // scan-ok: own translation table, mdToHtml escapes first
  const w=document.getElementById('help-warn'); if(w) w.hidden=true;
  const dlg=document.getElementById('help'); if(dlg.showModal) dlg.showModal(); else dlg.setAttribute('open','');
}
function closeHelp(){ const dlg=document.getElementById('help'); if(dlg&&dlg.close) dlg.close(); else if(dlg) dlg.removeAttribute('open'); }
// German docs are NAME.de.md, English docs NAME.md (README neutral, GUIDE is GUIDE.<lang>.md).
function docFile(name){ if(name==='README') return 'README.md'; if(name==='GUIDE') return 'GUIDE.'+lang+'.md'; return lang==='de'?name+'.de.md':name+'.md'; }
function docBaseName(url){ return url.replace(/[?#].*$/,'').replace(/\.(de|en)\.md$/i,'').replace(/\.md$/i,''); }
function docTitleFor(url){ const k={README:'footReadme',GUIDE:'footGuide',LICENSE:'footLicense',PRIVACY:'footPrivacy',TRADEMARKS:'footTrademarks',DISCLAIMER:'footDisclaimer'}[docBaseName(url)]; return k?t(k):docBaseName(url); }
// Make ticket links inside rendered docs open the same prefilled issue as the footer "Fehler melden" (incl. live log).
function hookIssueLinks(container){
  if(!container) return;
  const footBtn=document.querySelector('[data-t="footIssue"]'); if(!footBtn) return; // no footer hook -> leave the plain href
  container.querySelectorAll('a[href*="Laufbursche42/Laufbursche42/issues"]').forEach(a=>{
    a.setAttribute('role','button');
    a.addEventListener('click',e=>{ e.preventDefault(); footBtn.click(); }); // reuse the footer's prefill (report-footer.js, shared verbatim), incl. live log
  });
}
async function openDoc(file,title){
  const dlg=document.getElementById('doc'); document.getElementById('doc-title').textContent=title; document.getElementById('doc-body').textContent=t('docLoading')||'…';
  if(!dlg.open){ if(dlg.showModal) dlg.showModal(); else dlg.setAttribute('open',''); }
  try{ const r=await fetch(file); const md=await r.text(); const db=document.getElementById('doc-body'); db.innerHTML=mdToHtml(md); db.scrollTop=0; hookIssueLinks(db); } // scan-ok: markdown of our own documents, mdToHtml escapes first
  catch(e){ document.getElementById('doc-body').textContent=(t('docLoadErr')||'Load error: ')+file+' ('+e+')'; }
}
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
function inlineMd(s){
  return s
    .replace(/`([^`]+)`/g,'<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g,function(m,text,href){
      if(/^(https?:)?\/\//i.test(href)||/^mailto:/i.test(href)) return '<a href="'+href+'" target="_blank" rel="noopener">'+text+'</a>';
      if(/^#/.test(href)) return '<a href="#" data-anchor="'+href+'">'+text+'</a>';
      if(/\.md(?:[?#].*)?$/i.test(href)) return '<a href="#" data-doclink="'+href+'">'+text+'</a>';
      return '<a href="'+href+'" target="_blank" rel="noopener">'+text+'</a>';
    });
}
function mdToHtml(md){
  var codeBlocks=[];
  md=String(md).replace(/```[^\n]*\n?([\s\S]*?)```/g,function(m,code){ var i=codeBlocks.length; codeBlocks.push('<pre><code>'+esc(code.replace(/\n$/,''))+'</code></pre>'); return '\x00CB'+i+'\x00'; });
  var lines=md.split(/\r?\n/);
  var out=[],para=[],list=null;
  function flushPara(){ if(para.length){ out.push('<p>'+inlineMd(esc(para.join(' ')))+'</p>'); para=[]; } }
  function flushList(){ if(list){ out.push('<'+list.type+'>'+list.items.join('')+'</'+list.type+'>'); list=null; } }
  function isTableSep(s){ var tt=s.replace(/\s/g,''); return /^\|?:?-+:?(\|:?-+:?)+\|?$/.test(tt); }
  function splitRow(s){ return s.trim().replace(/^\|/,'').replace(/\|$/,'').split('|').map(function(c){ return c.trim(); }); }
  for(var i=0;i<lines.length;i++){
    var ln=lines[i];
    var cb=ln.match(/^\x00CB(\d+)\x00$/);
    if(cb){ flushPara(); flushList(); out.push(codeBlocks[Number(cb[1])]); continue; }
    if(/^\s*$/.test(ln)){ flushPara(); flushList(); continue; }
    var h=ln.match(/^(#{1,6})\s+(.*)$/);
    if(h){ flushPara(); flushList(); var lvl=Math.min(h[1].length,4); out.push('<h'+lvl+'>'+inlineMd(esc(h[2]))+'</h'+lvl+'>'); continue; }
    if(/^---+$/.test(ln.trim())){ flushPara(); flushList(); out.push('<hr>'); continue; }
    if(ln.indexOf('|')>=0&&i+1<lines.length&&isTableSep(lines[i+1])){
      flushPara(); flushList();
      var head=splitRow(ln); i++;
      var body='';
      while(i+1<lines.length&&lines[i+1].indexOf('|')>=0&&lines[i+1].trim()!==''){ body+='<tr>'+splitRow(lines[++i]).map(function(c){ return '<td>'+inlineMd(esc(c))+'</td>'; }).join('')+'</tr>'; }
      out.push('<table><thead><tr>'+head.map(function(c){ return '<th>'+inlineMd(esc(c))+'</th>'; }).join('')+'</tr></thead><tbody>'+body+'</tbody></table>');
      continue;
    }
    if(/^\s*>/.test(ln)){
      flushPara(); flushList();
      var q=[];
      while(i<lines.length&&/^\s*>/.test(lines[i])){ q.push(lines[i].replace(/^\s*>\s?/,'')); i++; }
      i--;
      while(q.length&&/^\s*$/.test(q[0])) q.shift();
      while(q.length&&/^\s*$/.test(q[q.length-1])) q.pop();
      if(q.length) out.push('<blockquote>'+mdToHtml(q.join('\n'))+'</blockquote>');
      continue;
    }
    var ul=ln.match(/^\s*[-*]\s+(.*)$/);
    var ol=ln.match(/^\s*\d+\.\s+(.*)$/);
    if(ul||ol){
      flushPara();
      var type=ul?'ul':'ol';
      if(!list||list.type!==type){ flushList(); list={type:type,items:[]}; }
      list.items.push('<li>'+inlineMd(esc((ul?ul[1]:ol[1])))+'</li>');
      continue;
    }
    para.push(ln.trim());
  }
  flushPara(); flushList();
  return out.join('\n');
}

// ---- UI ----
function t(key){ const T=(typeof window!=='undefined')&&window.I18N; const v=T&&T[lang]&&T[lang][key]; return (typeof v==='string')?v:''; } // returns the table value or '' (never the key/DOM text) - keeps getAttribute('data-t') out of innerHTML (CodeQL js/xss-through-dom)
function switchLang(l){ lang=l; try{ localStorage.setItem('segway_lang',l); }catch(e){}
  document.querySelectorAll('#langs button').forEach(b=>b.setAttribute('aria-pressed',String(b.getAttribute('data-lang')===l)));
  document.querySelectorAll('[data-t]').forEach(el=>{ const k=el.getAttribute('data-t'); const s=t(k); if(el.tagName==='INPUT'&&el.type==='button') el.value=s; else if(/[<&]/.test(s)) el.innerHTML=s; else el.textContent=s; }); // scan-ok: own translation table
  const ms=document.getElementById('model-sel'); if(ms) ms.querySelectorAll('optgroup').forEach((og,gi)=>{ if(MODEL_GROUPS[gi]) og.label=t(MODEL_GROUPS[gi].gkey)||og.label; });
  document.documentElement.lang=l;
}
function initUI(){
  const on=(id,ev,fn)=>{ const e=document.getElementById(id); if(e) e.addEventListener(ev,fn); };
  on('btn-conn','click',()=>connected?disconnect():connect());
  on('btn-set-speed','click',()=>{ const v=parseFloat(document.getElementById('speed-in').value); if(v>0) setSpeed(v); });
  on('btn-set-mode','click',()=>setMode(parseInt(document.getElementById('mode-in').value)));
  on('btn-set-kers','click',()=>setKERS(parseInt(document.getElementById('kers-in').value)));
  on('btn-set-cruise','click',()=>setCruise(parseInt(document.getElementById('cruise-in').value)===1));
  on('btn-set-taillight','click',()=>setTailLight(parseInt(document.getElementById('taillight-in').value)===1));
  on('btn-set-volume','click',()=>{ const v=parseInt(document.getElementById('volume-in').value); if(v>=0) setVolume(v); });

  on('sl-on','click',()=>{ const v=parseFloat(document.getElementById('sl-kmh').value); if(v>0) setSpeed(v); });
  on('sl-off','click',()=>setSpeedLimitOff());
  on('sn-backup','click',doBackup);
  on('sn-write','click',()=>writeSerial(document.getElementById('sn-new').value));
  on('sn-restore','click',restoreSn);
  on('sn-ack','change',refreshControls);

  on('raw-read','click',rawRead);
  on('raw-write','click',rawWrite);
  on('raw-preset','change',e=>{ const p=RAW_PRESETS[parseInt(e.target.value,10)]; if(!p) return;
    document.getElementById('raw-board').value=String(p.board);
    document.getElementById('raw-reg').value='0x'+hex2(p.reg);
    if(p.len) document.getElementById('raw-len').value=String(p.len);
    document.getElementById('raw-val').value=p.val||''; });

  on('gen-sel','change',e=>{ const v=e.target.value; encrypted=(v!=='legacy'); proto=(v==='gen2')?GEN.gen2:GEN.gen3; log('Krypto: '+v); });
  on('model-sel','change',e=>applyModel(parseInt(e.target.value,10)));

  on('btn-theme','click',()=>{ const cur=document.documentElement.getAttribute('data-theme'),next=cur==='light'?'dark':'light'; document.documentElement.setAttribute('data-theme',next); const b=document.getElementById('btn-theme'); if(b) b.textContent=next==='dark'?'☀':'☾'; try{localStorage.setItem('segway_theme',next);}catch(e){} });
  on('langs','click',e=>{ const btn=e.target.closest('button'); if(btn) switchLang(btn.getAttribute('data-lang')); });

  document.querySelectorAll('[data-t]').forEach(el=>{ const k=el.getAttribute('data-t'); const s=t(k); if(el.tagName==='INPUT'&&el.type==='button') el.value=s; else if(/[<&]/.test(s)) el.innerHTML=s; else el.textContent=s; }); // scan-ok: own translation table
  let sl; try{ sl=localStorage.getItem('segway_lang'); }catch(e){} if(sl) switchLang(sl);
  initRaw(); initModels();

  // ---- canonical shell wiring: footer version, log + anonymization, doc/help dialogs ----
  const bv=document.getElementById('build-ver'); if(bv) bv.textContent='build '+BUILD;
  { const pc=document.getElementById('public-log'); if(pc){ pc.checked=publicLog; pc.addEventListener('change',()=>{ publicLog=pc.checked; try{localStorage.setItem('segway_publiclog',publicLog?'1':'0');}catch(e){} log('public-log: '+(publicLog?'on (anonymizing device name/id)':'off')); renderLog(); }); } }
  { const dc=document.getElementById('diag-log'); if(dc){ dc.checked=diagLog; dc.addEventListener('change',()=>{ diagLog=dc.checked; try{localStorage.setItem('segway_diaglog',diagLog?'1':'0');}catch(e){} log('diag-log: '+(diagLog?'on':'off')); }); } }
  on('btn-copy-log','click',copyLog); on('btn-clear-log','click',clearLog); on('btn-save-log','click',saveLog);
  document.addEventListener('click',e=>{ const b=e.target.closest&&e.target.closest('.help-btn'); if(b){ e.preventDefault(); openHelp(b.getAttribute('data-help')); } });
  ['help-x','help-close'].forEach(id=>{ const b=document.getElementById(id); if(b) b.addEventListener('click',closeHelp); });
  ['doc-x','doc-close'].forEach(id=>{ const b=document.getElementById(id); if(b) b.addEventListener('click',()=>{ const d=document.getElementById('doc'); if(d&&d.close) d.close(); }); });
  // Delegate on document so links injected later by switchLang() (e.g. startHintGuide) also open the dialog.
  document.addEventListener('click',e=>{ const a=e.target.closest&&e.target.closest('[data-doc]'); if(!a) return; e.preventDefault(); const name=a.getAttribute('data-doc'); openDoc(docFile(name),(a.textContent||name).trim()); });
  { const db=document.getElementById('doc-body'); if(db) db.addEventListener('click',e=>{ const dl=e.target.closest&&e.target.closest('[data-doclink]'); if(dl){ e.preventDefault(); const href=dl.getAttribute('data-doclink'); openDoc(href,docTitleFor(href)); } }); }
  document.addEventListener('click',e=>{ const dd=e.target.closest&&e.target.closest('[data-open-disclaimer]'); if(dd){ e.preventDefault(); openDoc(docFile('DISCLAIMER'),t('footDisclaimer')); } });

  let st; try{ st=localStorage.getItem('segway_theme'); }catch(e){} document.documentElement.setAttribute('data-theme',st||'dark');
  setStatus('disconnected');
}
if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',initUI); else initUI();
