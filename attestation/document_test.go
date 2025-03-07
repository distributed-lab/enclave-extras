package attestation

import (
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

func TestParseNSMAttestationDoc(t *testing.T) {
	var tests = []struct {
		name  string
		input string
		want  error
	}{
		{
			name:  "Valid attestation document",
			input: "0x8444a1013822a0591342a9696d6f64756c655f69647827692d30663732323839353161653636343439622d656e633031393536313537333838653930383066646967657374665348413338346974696d657374616d701b000001956158afa46470637273b0005830000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000015830000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000025830000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000035830000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045830e5d3e79e1493e8cdfa15bf399aeb25d51d7b94267791095d20b5aed35418419d67d7553aff2cc38ca97ff7c954c3cc480558300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000658300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000758300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000858300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000958300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f58300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b63657274696669636174655902853082028130820207a003020102021001956157388e90800000000067c7002c300a06082a8648ce3d040303308191310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313c303a06035504030c33692d30663732323839353161653636343439622e65752d63656e7472616c2d312e6177732e6e6974726f2d656e636c61766573301e170d3235303330343133323931335a170d3235303330343136323931365a308196310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533141303f06035504030c38692d30663732323839353161653636343439622d656e63303139353631353733383865393038302e65752d63656e7472616c2d312e6177733076301006072a8648ce3d020106052b8104002203620004c682ea93f8303040d068ef4dd9321c626727ed472a85e4ceca11b171e8ad5af90f080a594f1197c4e056909717ff79926782a740a38f997e132a731eed38ec899e9573f3e534708dd8a83826b324f4e23bc89d07ca5037dff3257bcccafcbdbca31d301b300c0603551d130101ff04023000300b0603551d0f0404030206c0300a06082a8648ce3d0403030368003065023059bd5146e1e4af5b09447279f6c53c125f9d64e5dcc9a305b37402ecc0fc23662df794d25e3fc64e13eaeda88b32fe00023100ee9b90ea774f9f4eb5a51a2ee2cc720d95c00ea9cc000b7abc3f1b6b3fcd9362ee34428c2ea1e1bff0e6bb326ad5d99868636162756e646c65845902153082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3139313032383133323830355a170d3439313032383134323830355a3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a3423040300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff65902c5308202c130820248a003020102021100ec36ceb24203f43dd95a370124ee5622300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3235303330323230313233335a170d3235303332323231313233335a3067310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533139303706035504030c30633932306534643565373562353263382e65752d63656e7472616c2d312e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004a5f4550e1c03dd999eead3b5de9af37cbb046e563db7d4f6b196713c94420a8fa0b020aab89d5635cdbe66f968e5fb0e696097d288c2221cc66159f4c8fbfce11cf8f7df8cbfc209da344bf4f5a735762543ae096d3d380eec62c20df5bcc21da381d53081d230120603551d130101ff040830060101ff020102301f0603551d230418301680149025b50dd90547e796c396fa729dcf99a9df4b96301d0603551d0e04160414a456dcb26e910b55d6af3a6968ffd22a26632a8a300e0603551d0f0101ff040403020186306c0603551d1f046530633061a05fa05d865b687474703a2f2f6177732d6e6974726f2d656e636c617665732d63726c2e73332e616d617a6f6e6177732e636f6d2f63726c2f61623439363063632d376436332d343262642d396539662d3539333338636236376638342e63726c300a06082a8648ce3d040303036700306402307dce01e4a8a49df096e9740403c693d4fc19f88b70f13e33116d37ba24cac1d667aabcefe3771e800e7fbe81dbba9d1a023008cd999b28ba7fc45afa42294fcb3bbe25d1b5c1d22c59df49aea728e361b70bec9c35f768c0574453eef2b8fdefa58659032530820321308202a7a003020102021100a0a3db1e991221ed747b59ea0b2c9d65300a06082a8648ce3d0403033067310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533139303706035504030c30633932306534643565373562353263382e65752d63656e7472616c2d312e6177732e6e6974726f2d656e636c61766573301e170d3235303330343034353631335a170d3235303331303034353631325a30818c313f303d06035504030c36646236343234323561383561323266352e7a6f6e616c2e65752d63656e7472616c2d312e6177732e6e6974726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257413110300e06035504070c0753656174746c653076301006072a8648ce3d020106052b810400220362000443bd996ffe4412888ec1a20f65c89ef4c1b4701ef08c63d299036be22f4149d97906e10df26c1d671fbed0437f2be319ce6905b21500327e99fffe5120236da8ae1c68c4e80af2a0bd02d0fe45209c79bf0d1eab1108b93d29ddb7626e6cb265a381f03081ed30120603551d130101ff040830060101ff020101301f0603551d23041830168014a456dcb26e910b55d6af3a6968ffd22a26632a8a301d0603551d0e041604147773e32caa1679f18434a1be6f06aa4e1bc70129300e0603551d0f0101ff0404030201863081860603551d1f047f307d307ba079a0778675687474703a2f2f63726c2d65752d63656e7472616c2d312d6177732d6e6974726f2d656e636c617665732e73332e65752d63656e7472616c2d312e616d617a6f6e6177732e636f6d2f63726c2f32373139633764302d376631332d346131382d383238322d6661363235333739613939632e63726c300a06082a8648ce3d040303036800306502305fdc37ff47d106629a95735c708b8ba9b0d4291efabcfa2010865a954432013bc743ec5a556e0347f385f136dffc1a26023100d4753a58e6f000f57822db409ef6844da2d1dd8a9e40c93c4b7c44f841fc92c69b7fd03f195fc63056cb0cf07fd1b03f5902c8308202c43082024ba003020102021500b2c6b594649a5460832b2282abdcb30629fe731b300a06082a8648ce3d04030330818c313f303d06035504030c36646236343234323561383561323266352e7a6f6e616c2e65752d63656e7472616c2d312e6177732e6e6974726f2d656e636c61766573310c300a060355040b0c03415753310f300d060355040a0c06416d617a6f6e310b3009060355040613025553310b300906035504080c0257413110300e06035504070c0753656174746c65301e170d3235303330343133323134375a170d3235303330353133323134375a308191310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313c303a06035504030c33692d30663732323839353161653636343439622e65752d63656e7472616c2d312e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b81040022036200047f39a46e459344b6d0076c81c5877aeb16f8ca7a801a7d23ac7d26fa84163fcf27a14d4d26b853b10e7a2a0bb3b8c1c6b9501769cab11be2b17613c6cdb6597d348fbcfd7125b71d7a0001cab748558695b012fbd8758e8e6f75242091219162a366306430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020204301d0603551d0e041604146e3625c57870eff910f88b26a811cb715a338755301f0603551d230418301680147773e32caa1679f18434a1be6f06aa4e1bc70129300a06082a8648ce3d04030303670030640230167eae61e0b7cfb2601989d32cdb74cbab497765c8d8cf23a51e07e6aa9f26760385edc571c5add1064f09852cf3d75f023047eeaeca6b8ff615780ff5ec1b9e246ed1ce5ca4104cc75c1abedcb5e36339f887bf00a0db2ea4bc56d279b8e0dc34436a7075626c69635f6b657959022630820222300d06092a864886f70d01010105000382020f003082020a0282020100e16391b40ea5ad0e3ffec71fdcf7f980eed2506c0652e1496815cca3ba24283360729a60026242ed75a10c54547011d7d6e5ae224a294f8b7e0d9757c8655ec83ad82589e832c0ea65cd9164211fc27259031186e11a90852976c81e3a0cc4d204bba8cec8100a0d34213c71993bda6b9ae549a37b3d3fec79beca6e00f2323b7ba91b363f26c71be98b581615ded2f8b6c9d5bf0e6d0eb7428547ab127a3b10981b23147412c8b63e16eb24f470da4fdc638b8e11991e6f43fe4f870b66ef67b5d4003c3e41153e64dcc05507563f8ebda6c2ba14fb445975eaef59d5dda3bbff13e7149f7a6ed1ea68d2898d47ac4246ca766b60ba62cb454a82df083fbdda8b17c5446861315a90da2cdb30ceffddab3ad481dba153063180c144116bdeab41ecf7e10ef522afcc695ff0602ccec47e95714aade3eb6507b4c3db8b94dd8c11c3ee42876694af746763fab41332810fb58f1d51b364747ce691940194af89b681b7eb18e4675500393221db6eebdf6711ee0c855e15cc5462f88e6359a3789b99059ced5d1476ee86b92cbbda7b652955e584c50aa9400f2a5c99eaf7a97afbd612006168956bb94bd556be53bd0d022790566b58dd0eb4b36da8d2d9f94662a45ff3710c1823abaaeb151f38e663c64d554cbec792f6a6c79d774803959a7296e30a4ec7b17280915921114ffcb1aca16003e76ea60f5cbf56d9aad18679020301000169757365725f6461746140656e6f6e6365405860d7ec9200cf711be384b75bd2452b195a8bd07678e835f5aadbc212b393e7a6441cf81194474c8c71f22ad993c34a3b222c480f4394342a1cb2198b3a00dd707d52fe30b745f362a60ca265e26345d70c3d13aa99cd5592dd94b81577bba0f0e7",
			want:  nil,
		},
	}

	for _, test := range tests {
		_, err := ParseNSMAttestationDoc(hexutil.MustDecode(test.input))
		if err != test.want {
			t.Errorf("got %v, want %v", err, test.want)
		}
	}
}
