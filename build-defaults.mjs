/* Signal EDI — default SEF builder.
 * Assembles simplified-but-useful HIPAA 5010 reference profiles from a shared
 * core, writes sef/<key>.sef, and emits js/default-sefs.js (embedded registry
 * so the app runs from file:// with no fetch). Run:  node build-defaults.mjs
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(fileURLToPath(import.meta.url));
mkdirSync(join(root, 'sef'), { recursive: true });

// ---- shared data element dictionary (num -> [type, min, max, name]) ----------
const ELM = {
  '143': ['ID', 3, 3, 'Transaction Set Identifier Code'],
  '329': ['AN', 4, 9, 'Transaction Set Control Number'],
  '96':  ['N0', 1, 10, 'Number of Included Segments'],
  '1705':['AN', 1, 35, 'Implementation Convention Reference'],
  '28':  ['N0', 1, 9, 'Group Control Number'],
  '479': ['ID', 2, 2, 'Functional Identifier Code'],
  '480': ['AN', 1, 12, 'Version / Release / Industry Identifier Code'],
  '455': ['ID', 1, 2, 'Responsible Agency Code'],
  '337': ['TM', 4, 8, 'Time'],
  '373': ['DT', 8, 8, 'Date'],
  '353': ['ID', 2, 2, 'Transaction Set Purpose Code'],
  '640': ['ID', 2, 2, 'Transaction Type Code'],
  '127': ['AN', 1, 50, 'Reference Identification'],
  '128': ['ID', 2, 3, 'Reference Identification Qualifier'],
  '1005':['AN', 1, 4, 'Hierarchical Structure Code'],
  '1069':['AN', 1, 12, 'Hierarchical ID Number'],
  '734': ['AN', 1, 12, 'Hierarchical Parent ID Number'],
  '735': ['ID', 1, 2, 'Hierarchical Level Code'],
  '736': ['ID', 1, 1, 'Hierarchical Child Code'],
  '98':  ['ID', 2, 3, 'Entity Identifier Code'],
  '1065':['ID', 1, 1, 'Entity Type Qualifier'],
  '1035':['AN', 1, 60, 'Name Last or Organization Name'],
  '1036':['AN', 1, 35, 'Name First'],
  '1037':['AN', 1, 25, 'Name Middle'],
  '1038':['AN', 1, 10, 'Name Prefix'],
  '1039':['AN', 1, 10, 'Name Suffix'],
  '66':  ['ID', 1, 2, 'Identification Code Qualifier'],
  '67':  ['AN', 2, 80, 'Identification Code'],
  '166': ['AN', 1, 55, 'Address Information'],
  '19':  ['AN', 2, 30, 'City Name'],
  '156': ['ID', 2, 2, 'State or Province Code'],
  '116': ['ID', 3, 15, 'Postal Code'],
  '26':  ['ID', 2, 3, 'Country Code'],
  '365': ['ID', 2, 2, 'Communication Number Qualifier'],
  '364': ['AN', 1, 256, 'Communication Number'],
  '1068':['ID', 1, 1, 'Gender Code'],
  '1250':['ID', 2, 3, 'Date Time Period Format Qualifier'],
  '1251':['AN', 1, 35, 'Date Time Period'],
  '374': ['ID', 3, 3, 'Date/Time Qualifier'],
  '782': ['R', 1, 18, 'Monetary Amount'],
  '380': ['R', 1, 15, 'Quantity'],
  '355': ['ID', 2, 2, 'Unit or Basis for Measurement Code'],
  '235': ['ID', 2, 2, 'Product/Service ID Qualifier'],
  '234': ['AN', 1, 48, 'Product/Service ID'],
  '1028':['AN', 1, 38, 'Claim Submitter Identifier'],
  '1073':['ID', 1, 1, 'Yes/No Condition or Response Code'],
  '1032':['ID', 1, 2, 'Claim Filing Indicator Code'],
  '584': ['ID', 1, 2, 'Employment Status Code'],
  '1204':['ID', 2, 2, 'Plan Coverage Description'],
  '309': ['ID', 1, 2, 'Location Qualifier'],
  '1131':['AN', 1, 30, 'Code Category'],
  '1136':['ID', 1, 2, 'Code List Qualifier Code'],
  '1339':['AN', 1, 2, 'Procedure Modifier'],
  '594': ['ID', 2, 2, 'Frequency Qualifier'],
  '673': ['ID', 2, 2, 'Quantity Qualifier'],
  '522': ['ID', 1, 2, 'Amount Qualifier Code'],
  '1250b':['ID', 2, 3, 'x'],
  '609': ['N0', 1, 3, 'Count'],
  '810': ['ID', 2, 2, 'Bill Type / Category'],
  '507': ['ID', 3, 3, 'Claim Adjustment Reason (group)'],
  '1033':['ID', 1, 2, 'Claim Adjustment Group Code'],
  '1034':['ID', 1, 5, 'Claim Adjustment Reason Code'],
  '86':  ['R', 1, 18, 'Total Claim Charge / Monetary Amount'],
  '585': ['ID', 1, 2, 'Provider Code'],
  '591': ['ID', 1, 1, 'Payment Method Code'],
  '812': ['ID', 1, 2, 'Payment Format Code'],
  '506': ['ID', 2, 3, 'DFI ID Number Qualifier'],
  '507b':['AN', 3, 12, 'DFI Identification Number'],
  '569': ['ID', 2, 2, 'Account Number Qualifier'],
  '508': ['AN', 1, 35, 'Account Number'],
  '481': ['ID', 1, 2, 'Payment Action Code'],
  '552': ['ID', 1, 2, 'Payment Category (BPR)'],
  '558': ['ID', 2, 2, 'Adjustment Reason Code'],
  '104': ['ID', 1, 2, 'Benefit Status Code'],
  '1390':['ID', 1, 2, 'Coverage Level Code'],
  '875': ['ID', 3, 3, 'Maintenance Type Code'],
  '1203':['ID', 1, 2, 'Maintenance Reason Code'],
  '1216':['ID', 1, 1, 'Benefit Status Code'],
  '1219':['ID', 1, 1, 'Employment Status'],
  '271':  ['ID', 3, 3, 'Insurance Line Code'],
  '875b':['ID', 3, 3, 'x'],
  '1207':['ID', 3, 3, 'Related Entity'],
  '306': ['ID', 2, 2, 'Action Code'],
  '346': ['ID', 2, 2, 'Application Type / Purpose'],
  '1325':['ID', 1, 2, 'Claim Status Category Code'],
  '1271':['AN', 1, 30, 'Industry Code'],
  '1073b':['ID',1,1,'x'],
  '1322':['ID', 1, 1, 'Claim Payment Remark'],
  '1242':['ID', 1, 2, 'Related Causes Code'],
  '1000':['ID', 2, 2, 'Note Reference Code'],
  '352': ['AN', 1, 264, 'Description'],
  '659': ['ID', 1, 1, 'Basis of Verification'],
  '106': ['ID', 1, 1, 'Time Code'],
  // interchange / group envelope elements
  'I01': ['ID', 2, 2, 'Authorization Information Qualifier'],
  'I02': ['AN', 10, 10, 'Authorization Information'],
  'I03': ['ID', 2, 2, 'Security Information Qualifier'],
  'I04': ['AN', 10, 10, 'Security Information'],
  'I05': ['ID', 2, 2, 'Interchange ID Qualifier'],
  'I06': ['AN', 15, 15, 'Interchange Sender / Receiver ID'],
  'I07': ['AN', 15, 15, 'Interchange Receiver ID'],
  'I08': ['DT', 6, 6, 'Interchange Date'],
  'I09': ['TM', 4, 4, 'Interchange Time'],
  'I10': ['AN', 1, 1, 'Repetition Separator'],
  'I11': ['ID', 5, 5, 'Interchange Control Version Number'],
  'I12': ['N0', 9, 9, 'Interchange Control Number'],
  'I13': ['ID', 1, 1, 'Acknowledgment Requested'],
  'I14': ['ID', 1, 1, 'Interchange Usage Indicator'],
  'I15': ['AN', 1, 1, 'Component Element Separator'],
  'I16': ['N0', 1, 5, 'Number of Included Functional Groups'],
  '142': ['AN', 2, 15, "Application Sender's Code"],
  '124': ['AN', 2, 15, "Application Receiver's Code"],
  '97':  ['N0', 1, 6, 'Number of Transaction Sets Included'],
};

// element codes: num -> [ [code, desc], ... ]
const CODES = {
  '143': [['837','Health Care Claim'],['835','Claim Payment/Advice'],['834','Benefit Enrollment'],
    ['270','Eligibility Inquiry'],['271','Eligibility Response'],['276','Claim Status Request'],
    ['277','Claim Status Response'],['278','Services Review'],['820','Premium Payment'],
    ['999','Implementation Acknowledgment'],['997','Functional Acknowledgment']],
  '455': [['X','Accredited Standards Committee X12']],
  '353': [['00','Original'],['18','Reissue'],['CH','Chargeable'],['RP','Repriced']],
  '1065':[['1','Person'],['2','Non-Person Entity']],
  '98':  [['41','Submitter'],['40','Receiver'],['85','Billing Provider'],['87','Pay-to Provider'],
    ['IL','Insured or Subscriber'],['QC','Patient'],['PR','Payer'],['82','Rendering Provider'],
    ['77','Service Location'],['DN','Referring Provider'],['DK','Ordering Provider'],['31','Postal Mailing Address'],['P5','Plan Sponsor'],['IN','Insurer'],['36','Employer']],
  '1068':[['M','Male'],['F','Female'],['U','Unknown']],
  '66':  [['XX','NPI (Centers for Medicare and Medicaid Services National Provider Identifier)'],['MI','Member Identification Number'],['PI','Payor Identification'],['46','Electronic Transmitter Identification Number'],['FI','Federal Taxpayer Identification Number'],['24','Employer Identification Number'],['34','Social Security Number']],
  '1005':[['0019','Information Source, Information Receiver, Subscriber, Dependent'],['0022','Info Source, Info Receiver, Subscriber']],
  '735': [['20','Information Source'],['21','Information Receiver'],['22','Subscriber'],['23','Dependent'],['19','Provider of Service']],
  '235': [['HC','Health Care Financing Administration Common Procedural Coding System (HCPCS)'],['AD','American Dental Association Codes'],['ER','Jurisdiction Specific Procedure'],['IV','HIEC'],['ND','National Drug Code']],
  '591': [['ACH','Automated Clearing House'],['BOP','Financial Institution Option'],['CHK','Check'],['FWT','Federal Reserve Funds/Wire Transfer'],['NON','Non-Payment Data']],
  '1250':[['D8','Date Expressed in CCYYMMDD Format'],['RD8','Range of Dates CCYYMMDD-CCYYMMDD'],['DT','Date and Time']],
  '374': [['434','Statement'],['435','Admission'],['472','Service'],['096','Discharge'],['090','Report Start'],['091','Report End'],['150','Service Period Start'],['151','Service Period End']],
  '1032':[['11','Other Non-Federal Programs'],['12','PPO'],['13','POS'],['14','EPO'],['15','Indemnity Insurance'],['16','HMO Medicare Risk'],['CI','Commercial Insurance Co.'],['MB','Medicare Part B'],['MC','Medicaid'],['ZZ','Mutually Defined']],
  '875': [['001','Change (Update)'],['021','Addition'],['024','Cancellation or Termination'],['025','Reinstatement'],['030','Audit or Compare']],
  '1073':[['Y','Yes'],['N','No'],['W','Not Applicable'],['U','Unknown']],
  'I14': [['P','Production Data'],['T','Test Data'],['I','Information']],
  'I05': [['ZZ','Mutually Defined'],['01','Duns (Dun & Bradstreet)'],['14','Duns Plus Suffix'],['20','Health Industry Number'],['27','Carrier Identification Number'],['28','Fiscal Intermediary Identification Number'],['30','U.S. Federal Tax Identification Number'],['33','NAIC Company Code']],
  '455f':[],
};
delete CODES['455f'];

function typeName() {}

// ---- shared segment dictionary (id -> [name, [ [elem, req, max?], ... ] ]) ---
const SEG = {
  ISA: ['Interchange Control Header', [['I01','M'],['I02','O'],['I03','M'],['I04','O'],['I05','M'],['I06','M'],['I05','M'],['I07','M'],['I08','M'],['I09','M'],['I10','M'],['I11','M'],['I12','M'],['I13','M'],['I14','M'],['I15','M']]],
  IEA: ['Interchange Control Trailer', [['I16','M'],['I12','M']]],
  GS:  ['Functional Group Header', [['479','M'],['142','M'],['124','M'],['373','M'],['337','M'],['28','M'],['455','M'],['480','M']]],
  GE:  ['Functional Group Trailer', [['97','M'],['28','M']]],
  ST:  ['Transaction Set Header', [['143','M'],['329','M'],['1705','O']]],
  SE:  ['Transaction Set Trailer', [['96','M'],['329','M']]],
  BHT: ['Beginning of Hierarchical Transaction', [['1005','M'],['353','M'],['127','O'],['373','O'],['337','O'],['640','O']]],
  HL:  ['Hierarchical Level', [['1069','M'],['734','O'],['735','M'],['736','O']]],
  NM1: ['Individual or Organizational Name', [['98','M'],['1065','M'],['1035','O'],['1036','O'],['1037','O'],['1038','O'],['1039','O'],['66','O'],['67','O']]],
  N3:  ['Party Location (Address)', [['166','M'],['166','O']]],
  N4:  ['Geographic Location', [['19','O'],['156','O'],['116','O'],['26','O']]],
  PER: ['Administrative Communications Contact', [['366','O'],['93','O'],['365','O'],['364','O'],['365','O'],['364','O']]],
  REF: ['Reference Information', [['128','M'],['127','O'],['352','O']]],
  DTP: ['Date or Time or Period', [['374','M'],['1250','M'],['1251','M']]],
  DMG: ['Demographic Information', [['1250','O'],['1251','O'],['1068','O']]],
  PRV: ['Provider Information', [['585','M'],['1136','O'],['127','O']]],
  N1:  ['Party Identification', [['98','M'],['93','O'],['66','O'],['67','O']]],
  TRN: ['Trace', [['481','M'],['127','M'],['509','O'],['127','O']]],
  AMT: ['Monetary Amount Information', [['522','M'],['782','M']]],
  QTY: ['Quantity Information', [['673','M'],['380','O']]],
  DTM: ['Date/Time Reference', [['374','M'],['373','O'],['337','O']]],
  // 837
  CLM: ['Health Care Claim', [['1028','M'],['782','O'],['1032','O'],['1032b','O'],['C023','O'],['1073','O'],['1359','O'],['1073b','O']]],
  SBR: ['Subscriber Information', [['1138','M'],['1069','O'],['127','O'],['93','O'],['1336','O'],['584','O'],['584b','O'],['1143','O'],['1032','O']]],
  PAT: ['Patient Information', [['1069','O'],['1384','O'],['584','O'],['1220','O'],['1250','O'],['1251','O'],['355','O'],['81','O']]],
  HI:  ['Health Care Diagnosis / Information Codes', [['C022','M'],['C022','O'],['C022','O'],['C022','O']]],
  LX:  ['Service Line Number', [['554','M']]],
  SV1: ['Professional Service', [['C003','M'],['782','M'],['355','M'],['380','O'],['1331','O'],['1365','O']]],
  SV2: ['Institutional Service Line', [['234','M'],['C003','O'],['782','M'],['355','M'],['380','O']]],
  SV3: ['Dental Service', [['C003','M'],['782','O'],['1331','O'],['1358','O'],['380','O']]],
  CN1: ['Contract Information', [['1166','M'],['782','O']]],
  // 835
  BPR: ['Financial Information', [['305','M'],['782','M'],['478','M'],['591','M'],['812','O'],['506','O'],['569','O'],['508','O'],['509','O'],['510','O'],['506b','O'],['569b','O'],['508b','O'],['373','O']]],
  CLP: ['Claim Payment Information', [['1028','M'],['1029','M'],['782','M'],['782b','M'],['782c','O'],['1032','M'],['127','M'],['1331','O'],['1325','O']]],
  CAS: ['Claim Adjustment', [['1033','M'],['1034','M'],['782','M'],['380','O'],['1034b','O'],['782b','O']]],
  SVC: ['Service Payment Information', [['C003','M'],['782','M'],['782b','M'],['234','O'],['380','O']]],
  PLB: ['Provider Adjustment', [['127','M'],['373','M'],['C042','M'],['782','M']]],
  TS3: ['Provider Summary Information', [['127','M'],['1331','M'],['373','M'],['380','M'],['782','M']]],
  // 834
  BGN: ['Beginning Segment', [['353','M'],['127','M'],['373','M'],['337','O'],['623','O'],['127b','O'],['640','O'],['306','O']]],
  INS: ['Member Level Detail', [['1073','M'],['1069','M'],['875','M'],['1203','O'],['1216','O'],['1219','O'],['584','O']]],
  HD:  ['Health Coverage', [['875','M'],['1203','O'],['1204','M'],['1205','O'],['1390','O']]],
  DSB: ['Disability Information', [['1146','M'],['609','O']]],
  // 270/271
  EQ:  ['Eligibility or Benefit Inquiry', [['1365','O'],['C003','O'],['1207','O'],['1390','O']]],
  EB:  ['Eligibility or Benefit Information', [['1390','M'],['1207','O'],['1365','O'],['1336','O'],['1204','O'],['615','O'],['522','O'],['782','O']]],
  III: ['Information', [['1270','O'],['1271','O'],['1136','O'],['933','O']]],
  // 276/277
  BHTx:['Beginning', []],
  STC: ['Status Information', [['C043','M'],['373','O'],['306','O'],['782','O'],['782b','O']]],
  // 278
  UM:  ['Health Care Services Review', [['1525','M'],['1322','M'],['1365','O'],['C024','O'],['1338','O']]],
  HCR: ['Health Care Services Review', [['306','M'],['127','O'],['901','O']]],
  // 820
  RMR: ['Remittance Advice Accounts Receivable Open Item Ref', [['128','M'],['127','O'],['482','O'],['782','O'],['782b','O']]],
  ENT: ['Entity', [['554','O'],['98','O'],['66','O'],['67','O']]],
  // 999/997
  AK1: ['Functional Group Response Header', [['479','M'],['28','M'],['480','O']]],
  AK2: ['Transaction Set Response Header', [['143','M'],['329','M'],['1705','O']]],
  IK3: ['Error Identification', [['721','M'],['719','O'],['618','O'],['620','O']]],
  IK5: ['Transaction Set Response Trailer', [['717','M'],['618','O']]],
  AK9: ['Functional Group Response Trailer', [['715','M'],['97','M'],['123','M'],['2','M']]],
  CTX: ['Context', [['C998','O']]],
};

// Fill in loosely-typed elements referenced above but not in ELM, so the
// segment element list still renders with a ref + generic attributes.
const GENERIC = ['366','93','1032b','C023','1359','1138','1336','584b','1143','1384','1220',
  '81','C022','554','C003','1331','1365','1358','1166','305','478','509','510','506b','569b',
  '508b','1029','782b','782c','1034b','C042','623','127b','1205','1146','615','1270','933',
  '1525','C024','1338','901','482','C043','721','719','618','620','717','715','97','123','2',
  'C998','1206','1034b'];
GENERIC.forEach(n => { if (!ELM[n]) ELM[n] = ['AN', 0, 0, n.charAt(0) === 'C' ? 'Composite Element' : 'Data Element ' + n]; });

// sanitize a stray bad entry created above
ELM['1251'] = ['AN', 1, 35, 'Date Time Period'];
delete ELM['1250b']; delete ELM['875b']; delete ELM['507']; delete ELM['1073b'];

// ---- profile definitions -----------------------------------------------------
// Each: key, label, implRef, setId, [segment ids used], structure directives
function structure(lines) { return lines; }

const PROFILES = [
  {
    key: '837P', label: '837P — Professional Claim (005010X222A1)', implRef: '005010X222A1', setId: '837',
    segs: ['ST','SE','BHT','NM1','PER','N3','N4','REF','HL','SBR','PAT','DMG','PRV','CLM','HI','DTP','LX','SV1','CN1','AMT'],
    struct: [
      ['837','Health Care Claim: Professional'],
      'seg ST M 1','seg BHT M 1',
      'loop 1000A 1','seg NM1 M 1','seg PER O 2','end',
      'loop 1000B 1','seg NM1 M 1','end',
      'loop 2000A >1','seg HL M 1','seg PRV O 1',
      'loop 2010AA 1','seg NM1 M 1','seg N3 O 1','seg N4 O 1','seg REF O 8','end',
      'loop 2000B >1','seg HL M 1','seg SBR M 1',
      'loop 2010BA 1','seg NM1 M 1','seg N3 O 1','seg N4 O 1','seg DMG O 1','end',
      'loop 2010BB 1','seg NM1 M 1','end',
      'loop 2300 100','seg CLM M 1','seg DTP O 150','seg HI O 25',
      'loop 2400 999','seg LX M 1','seg SV1 M 1','seg DTP O 15','end','end','end','end',
      'seg SE M 1'
    ]
  },
  {
    key: '837I', label: '837I — Institutional Claim (005010X223A2)', implRef: '005010X223A2', setId: '837',
    segs: ['ST','SE','BHT','NM1','PER','N3','N4','REF','HL','SBR','PAT','DMG','PRV','CLM','HI','DTP','LX','SV2','CN1','AMT'],
    struct: [
      ['837','Health Care Claim: Institutional'],
      'seg ST M 1','seg BHT M 1',
      'loop 1000A 1','seg NM1 M 1','seg PER O 2','end',
      'loop 1000B 1','seg NM1 M 1','end',
      'loop 2000A >1','seg HL M 1',
      'loop 2010AA 1','seg NM1 M 1','seg N3 O 1','seg N4 O 1','end',
      'loop 2000B >1','seg HL M 1','seg SBR M 1',
      'loop 2010BA 1','seg NM1 M 1','seg DMG O 1','end',
      'loop 2300 100','seg CLM M 1','seg DTP O 150','seg HI O 25',
      'loop 2400 999','seg LX M 1','seg SV2 M 1','end','end','end','end',
      'seg SE M 1'
    ]
  },
  {
    key: '837D', label: '837D — Dental Claim (005010X224A2)', implRef: '005010X224A2', setId: '837',
    segs: ['ST','SE','BHT','NM1','PER','N3','N4','REF','HL','SBR','DMG','PRV','CLM','HI','DTP','LX','SV3'],
    struct: [
      ['837','Health Care Claim: Dental'],
      'seg ST M 1','seg BHT M 1',
      'loop 1000A 1','seg NM1 M 1','end',
      'loop 2000A >1','seg HL M 1',
      'loop 2000B >1','seg HL M 1','seg SBR M 1',
      'loop 2300 100','seg CLM M 1','seg DTP O 150',
      'loop 2400 999','seg LX M 1','seg SV3 M 1','end','end','end','end',
      'seg SE M 1'
    ]
  },
  {
    key: '835', label: '835 — Claim Payment / Remittance (005010X221A1)', implRef: '005010X221A1', setId: '835',
    segs: ['ST','SE','BPR','TRN','REF','DTM','N1','N3','N4','PER','LX','TS3','CLP','CAS','NM1','SVC','DTP','AMT','QTY','PLB'],
    struct: [
      ['835','Health Care Claim Payment/Advice'],
      'seg ST M 1','seg BPR M 1','seg TRN M 1','seg REF O 1','seg DTM O 1',
      'loop 1000A 1','seg N1 M 1','seg N3 O 1','seg N4 O 1','seg PER O 1','end',
      'loop 1000B 1','seg N1 M 1','seg N3 O 1','seg N4 O 1','end',
      'loop 2000 >1','seg LX M 1','seg TS3 O 1',
      'loop 2100 >1','seg CLP M 1','seg CAS O 99','seg NM1 O 1','seg DTM O 1','seg AMT O 20',
      'loop 2110 999','seg SVC M 1','seg DTM O 1','seg CAS O 99','seg AMT O 20','end','end','end',
      'seg PLB O 1','seg SE M 1'
    ]
  },
  {
    key: '834', label: '834 — Benefit Enrollment (005010X220A1)', implRef: '005010X220A1', setId: '834',
    segs: ['ST','SE','BGN','REF','DTP','N1','INS','NM1','PER','N3','N4','DMG','HD','DSB','AMT','LX'],
    struct: [
      ['834','Benefit Enrollment and Maintenance'],
      'seg ST M 1','seg BGN M 1','seg REF O 1','seg DTP O 1',
      'loop 1000A 1','seg N1 M 1','end',
      'loop 1000B 1','seg N1 M 1','end',
      'loop 2000 >1','seg INS M 1','seg REF O 1','seg DTP O 24',
      'loop 2100A 1','seg NM1 M 1','seg PER O 1','seg N3 O 1','seg N4 O 1','seg DMG O 1','end',
      'loop 2300 99','seg HD O 1','seg DTP O 24','seg AMT O 1','end','end',
      'seg SE M 1'
    ]
  },
  {
    key: '270', label: '270 — Eligibility Inquiry (005010X279A1)', implRef: '005010X279A1', setId: '270',
    segs: ['ST','SE','BHT','HL','NM1','REF','N3','N4','PRV','DMG','DTP','EQ','III'],
    struct: [
      ['270','Eligibility, Coverage or Benefit Inquiry'],
      'seg ST M 1','seg BHT M 1',
      'loop 2000A >1','seg HL M 1',
      'loop 2100A 1','seg NM1 M 1','end',
      'loop 2000B >1','seg HL M 1',
      'loop 2100B 1','seg NM1 M 1','end',
      'loop 2000C >1','seg HL M 1',
      'loop 2100C 1','seg NM1 M 1','seg REF O 9','seg DMG O 1','end',
      'loop 2110C 99','seg EQ M 1','seg DTP O 1','end','end','end','end',
      'seg SE M 1'
    ]
  },
  {
    key: '271', label: '271 — Eligibility Response (005010X279A1)', implRef: '005010X279A1', setId: '271',
    segs: ['ST','SE','BHT','HL','NM1','REF','N3','N4','PER','DMG','DTP','EB','III','MSG'],
    struct: [
      ['271','Eligibility, Coverage or Benefit Response'],
      'seg ST M 1','seg BHT M 1',
      'loop 2000A >1','seg HL M 1',
      'loop 2100A 1','seg NM1 M 1','end',
      'loop 2000C >1','seg HL M 1',
      'loop 2100C 1','seg NM1 M 1','seg DMG O 1',
      'loop 2110C 999','seg EB M 1','seg DTP O 20','seg REF O 9','end','end','end','end',
      'seg SE M 1'
    ]
  },
  {
    key: '276', label: '276 — Claim Status Request (005010X212)', implRef: '005010X212', setId: '276',
    segs: ['ST','SE','BHT','HL','NM1','TRN','REF','DTP','AMT','SVC'],
    struct: [
      ['276','Health Care Claim Status Request'],
      'seg ST M 1','seg BHT M 1',
      'loop 2000A >1','seg HL M 1',
      'loop 2100A 1','seg NM1 M 1','end',
      'loop 2000D >1','seg HL M 1',
      'loop 2200D 1','seg TRN M 1','seg REF O 1','seg DTP O 1',
      'loop 2210D 99','seg SVC O 1','seg REF O 1','seg DTP O 1','end','end','end','end',
      'seg SE M 1'
    ]
  },
  {
    key: '277', label: '277 — Claim Status Response (005010X212)', implRef: '005010X212', setId: '277',
    segs: ['ST','SE','BHT','HL','NM1','TRN','STC','REF','DTP','SVC','QTY','AMT'],
    struct: [
      ['277','Health Care Claim Status Response'],
      'seg ST M 1','seg BHT M 1',
      'loop 2000A >1','seg HL M 1',
      'loop 2100A 1','seg NM1 M 1','end',
      'loop 2000D >1','seg HL M 1',
      'loop 2200D 1','seg TRN M 1','seg STC M 1','seg REF O 1','seg DTP O 1',
      'loop 2220D 999','seg SVC O 1','seg STC O 99','seg DTP O 1','end','end','end','end',
      'seg SE M 1'
    ]
  },
  {
    key: '278', label: '278 — Services Review Request (005010X217)', implRef: '005010X217', setId: '278',
    segs: ['ST','SE','BHT','HL','NM1','REF','N3','N4','DMG','DTP','UM','HCR','HI','PRV'],
    struct: [
      ['278','Health Care Services Review Information'],
      'seg ST M 1','seg BHT M 1',
      'loop 2000A >1','seg HL M 1',
      'loop 2010A 1','seg NM1 M 1','end',
      'loop 2000E >1','seg HL M 1','seg UM M 1','seg HCR O 1','seg DTP O 9','seg HI O 1',
      'loop 2010EA 1','seg NM1 O 1','end','end',
      'seg SE M 1'
    ]
  },
  {
    key: '820', label: '820 — Premium Payment (005010X218)', implRef: '005010X218', setId: '820',
    segs: ['ST','SE','BPR','TRN','REF','DTM','N1','N3','N4','PER','ENT','NM1','RMR','AMT'],
    struct: [
      ['820','Payroll Deducted and Other Group Premium Payment'],
      'seg ST M 1','seg BPR M 1','seg TRN O 1','seg REF O 1','seg DTM O 1',
      'loop 1000A 1','seg N1 M 1','seg N3 O 1','seg N4 O 1','seg PER O 1','end',
      'loop 1000B 1','seg N1 M 1','end',
      'loop 2000 >1','seg ENT M 1',
      'loop 2300 >1','seg RMR M 1','seg REF O 1','seg DTM O 1','seg AMT O 1','end','end',
      'seg SE M 1'
    ]
  },
  {
    key: '999', label: '999 — Implementation Acknowledgment (005010X231A1)', implRef: '005010X231A1', setId: '999',
    segs: ['ST','SE','AK1','AK2','IK3','CTX','IK5','AK9'],
    struct: [
      ['999','Implementation Acknowledgment'],
      'seg ST M 1','seg AK1 M 1',
      'loop 2000 >1','seg AK2 O 1',
      'loop 2100 >1','seg IK3 O 1','seg CTX O 10','end','seg IK5 O 1','end',
      'seg AK9 M 1','seg SE M 1'
    ]
  }
];

// ---- rendering ---------------------------------------------------------------
function renderProfile(p) {
  const usedElms = new Set();
  const lines = [];
  lines.push('.SEF 1.6');
  lines.push('; Signal EDI simplified reference profile — not an exhaustive TR3 implementation guide.');
  lines.push('.STD');
  lines.push('X12|' + p.implRef + '|' + p.setId + '|' + p.label.replace(/^[^—]*—\s*/, '').replace(/\s*\(.*\)$/, ''));

  // segments (envelope control segments are included in every profile)
  const segLines = [], segTextLines = [];
  const allSegs = ['ISA', 'GS', 'GE', 'IEA'].concat(p.segs.filter(s => ['ISA', 'GS', 'GE', 'IEA'].indexOf(s) < 0));
  allSegs.forEach(id => {
    const s = SEG[id];
    if (!s) return;
    segTextLines.push(id + '=' + s[0]);
    const parts = [];
    s[1].forEach(e => {
      const num = e[0];
      usedElms.add(num.replace(/[a-z]$/, ''));
      parts.push(num.replace(/[a-z]$/, ''), e[1], e[2] || 1);
    });
    segLines.push(id + '=' + parts.join(','));
  });

  // elements + names + codes
  const elmLines = [], eleTextLines = [], codeLines = [], codeTextLines = [];
  const elmList = Array.from(usedElms).sort();
  elmList.forEach(num => {
    const d = ELM[num];
    if (!d) return;
    elmLines.push(num + '=' + d[0] + ',' + d[1] + ',' + d[2]);
    eleTextLines.push(num + '=' + d[3]);
    if (CODES[num] && CODES[num].length) {
      codeLines.push(num + '=' + CODES[num].map(c => c[0]).join(','));
      CODES[num].forEach(c => codeTextLines.push(num + ',' + c[0] + '=' + c[1]));
    }
  });

  lines.push('.ELMS'); elmLines.forEach(l => lines.push(l));
  lines.push('.CODES'); codeLines.forEach(l => lines.push(l));
  lines.push('.CODETEXT'); codeTextLines.forEach(l => lines.push(l));
  lines.push('.SEGS'); segLines.forEach(l => lines.push(l));
  lines.push('.SEGTEXT'); segTextLines.forEach(l => lines.push(l));
  lines.push('.ELETEXT'); eleTextLines.forEach(l => lines.push(l));
  lines.push('.SETS');
  p.struct.forEach(d => { lines.push(Array.isArray(d) ? d[0] + '=' + d[1] : d); });
  return lines.join('\n') + '\n';
}

const registry = {};
for (const p of PROFILES) {
  const text = renderProfile(p);
  writeFileSync(join(root, 'sef', p.key + '.sef'), text, 'utf8');
  registry[p.key] = { label: p.label, implRef: p.implRef, setId: p.setId, text };
}

const js = '/* Signal EDI — bundled HIPAA reference SEF profiles (generated by build-defaults.mjs).\n'
  + ' * Each is a simplified guideline for offline diagnostics; load a full .sef for complete validation. */\n'
  + 'window.DEFAULT_SEFS = ' + JSON.stringify(registry, null, 1) + ';\n';
writeFileSync(join(root, 'js', 'default-sefs.js'), js, 'utf8');

console.log('Wrote ' + PROFILES.length + ' SEF profiles to sef/ and js/default-sefs.js');
