
| Name                                  | Payload/Steps                                                                                                                                  | Resultant Key                                                                                                                    |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Broken Session Management             | 1. Open Networks<br />2. set lessonNotComplete to lessonComplete                                                                               | A49F4F676F9C59D3397559C88EFCE53296D29403FAE0C8E6604B7A02AAB505647FA854CCD952D696D32524F8B3465CE26DBA64FC40D8CBD54E645163B0F7BE55 |
| What is Cross Site Scripting (XSS)?   | `<SCRIPT>`alert('XSS')`</SCRIPT> `<br />``<IMG SRC="#" ONERROR="alert('XSS')"/>``<br />`<INPUT TYPE="BUTTON" ONCLICK="alert('XSS')"/>`  | 9E92D2934BB05CA9C7D5D8ABEC545AF1D919136A963D3FE2BB833566093E54794A5A471214C02EBB0C0B4BF9A4703B6094A7630E9E6DE49195EFA35896702C43 |
| Cross Site Scripting One              | `<iframe onload=alert(1)></iframe>`                                                                                                          | 036750E3E0D936EA1379310E68CB9D619D89819FF3B0C70FA148D4811C8E404CF454E4A67D9651D25EAA1172D2740A586ACD24BD1714E5AC5326AE73CC8B51AE |
| What is Mobile Insecure Data Storage? |                                                                                                                                                | Battery777                                                                                                                       |
| SQL Injection (Lesson)                |                                                                                                                                                | 3c17f6bf34080979e0cebda5672e989c07ceec9fa4ee7b7c17c9e3ce26bc63e                                                                  |

* SQL Injection One; key: fd8e9a29dab791197115b58061b215594211e72c1680f1eacc50b0394133a09f
* Session Management - 6081416B7EC996D5C6DEE1F7FCF6D016BA877259F9CEF3A4C852E85DE87015F073957583E9A8A05113982FBE3E7EED6E130183CAB5E82285618C50C728F01F54
* Mobile Reverse Engineering - DrumaDrumaDrumBoomBoom
* MobileUnintendedDataLeakage - SilentButSteadyRedLed
* Cross Site Request Forgery - http://localhost:8080/root/grantComplete/csrfLesson?userId=412477188; KEY: A12A4452503BB2758EBE9C3C833C81149C1C230B346A8EAAA99256E42E569A1468FAB2D266FB382D9876DDDAF47695B1EAA81A4C374789B4A6C77C2C7C175D09
* Content Provider Leakage - LazerLizardsFlamingWizards
*
