use crate::deserializers::{
    deserialize_evm_address, deserialize_hash, deserialize_str_to_from_str, deserialize_tm_addresses,
};
use crate::event_processor::EventHandler;
use crate::event_sub;
use crate::evm::error::Error;
use crate::evm::finalizer::Finalizer;
use crate::evm::json_rpc::EthereumClient;
use crate::evm::ChainName;
use crate::types::{EVMAddress, Hash, TMAddress};
use async_trait::async_trait;
use error_stack::{IntoReport, Report, Result, ResultExt};
use serde::de::value::MapDeserializer;
use serde::Deserialize;
use serde_json::{Map, Value};
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;
use web3::types::U64;

const EVENT_TYPE: &str = "axelar.evm.v1beta1.ConfirmGatewayTxStarted";

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Participants {
    #[serde(deserialize_with = "deserialize_str_to_from_str")]
    poll_id: u64,
    #[serde(deserialize_with = "deserialize_tm_addresses")]
    participants: Vec<TMAddress>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct Event {
    chain: String,
    #[serde(deserialize_with = "deserialize_hash")]
    tx_id: Hash,
    #[serde(deserialize_with = "deserialize_evm_address")]
    gateway_address: EVMAddress,
    #[serde(deserialize_with = "deserialize_str_to_from_str")]
    confirmation_height: u64,
    participants: Participants,
}

impl TryFrom<Map<String, Value>> for Event {
    type Error = Report<Error>;

    fn try_from(attributes: Map<String, Value>) -> Result<Event, Error> {
        Event::deserialize(MapDeserializer::new(attributes.into_iter()))
            .into_report()
            .change_context(Error::ParseEventError)
    }
}

pub struct Handler<F, C>
where
    F: Finalizer,
    C: EthereumClient,
{
    chain: ChainName,
    rpc_client: Arc<C>,
    finalizer: F,
}

impl<F, C> Handler<F, C>
where
    F: Finalizer,
    C: EthereumClient,
{
    pub fn new(chain: ChainName, finalizer: F, rpc_client: Arc<C>) -> Self {
        Self {
            chain,
            finalizer,
            rpc_client,
        }
    }
}

#[async_trait]
impl<F, C> EventHandler for Handler<F, C>
where
    F: Finalizer,
    C: EthereumClient,
{
    type Err = Error;

    async fn handle(&self, event: &event_sub::Event) -> Result<(), Self::Err> {
        let event: Event = match event {
            event_sub::Event::AbciEvent { event_type, attributes } if event_type.as_str() == EVENT_TYPE => {
                attributes.clone().try_into()?
            }
            _ => return Ok(()),
        };

        if !self.chain.matches(event.chain) {
            return Ok(());
        }

        let tx_receipt = self
            .rpc_client
            .transaction_receipt(event.tx_id)
            .await
            .change_context(Error::JSONRPCError)?;

        match tx_receipt {
            Some(tx_receipt)
                if self
                    .finalizer
                    .latest_finalized_block_height()
                    .await?
                    .ge(&tx_receipt.block_number.unwrap_or(U64::MAX)) =>
            {
                unimplemented!()
            }
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EVENT_TYPE;
    use crate::event_sub;
    use crate::handlers::evm_confirm_gateway_tx;
    use std::convert::TryInto;
    use tendermint::abci;

    #[test]
    fn deserialize_successful() {
        let event = abci::Event::new(
            "axelar.evm.v1beta1.ConfirmGatewayTxStarted",
            vec![
                ("chain", "\"Ethereum\""),
                ("gateway_address", "[79,68,149,36,56,55,104,16,97,196,116,59,116,179,238,223,84,141,86,165]"),
                ("tx_id", "[71,53,131,169,3,29,39,120,147,195,106,41,206,185,108,39,132,189,41,54,217,172,147,158,121,38,124,246,17,121,173,96]"),
                ("confirmation_height", "\"200\""),
                ("participants", "{\"poll_id\":\"41113\",\"participants\":[\"axelarvaloper1qy9uq03rkpqkzwsa4fz7xxetkxttdcj6tf09pg\",\"axelarvaloper1q2nyv5mwsu5r07x6djpgvm0jl9l9a5v88qllcd\",\"axelarvaloper1z9cz08mlfp6qz456zyzkw6epsjlzvr043m4rzz\",\"axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7\",\"axelarvaloper1zcsv9jp24nl0e4vha36l8dzypy363sw3rgq0zy\",\"axelarvaloper1rqp7vvl9cjmdan44dny56qadwg590uxv8hamux\",\"axelarvaloper1r7ppsrmzpslqu3d3yf344kzjv32n9dn4xyt0sw\",\"axelarvaloper1ypwzuhaffvr06ktu0ne6lnm69gxj32qwf94dg4\",\"axelarvaloper19ysyq74gkf8lv3l4suu3rlqadg4txp3sqxkhss\",\"axelarvaloper19dx6vywgr62jtsxhhlhlgh7ug5vmgjnz6dkeud\",\"axelarvaloper19wz0kfzj2czmjg9052h69wk6kgxc848hxs8rhl\",\"axelarvaloper1xy97mfxvm2qwtw7vt9e3m850eknxfwxd9l5ate\",\"axelarvaloper1x20lytyf6zkcrv5edpkfkn8sz578qg5s3j2wke\",\"axelarvaloper1xtawcxuvh3vtt6zht9pku3ltc0a76u209jl63x\",\"axelarvaloper1xesqr8vjvy34jhu027zd70ypl0nnev5ezjg5h9\",\"axelarvaloper18qydpumkn244ska4xw8890nc67l9e5qqm7c36r\",\"axelarvaloper186rt9fg3l6m9x2w9qxuvq80uapzhuezapyqser\",\"axelarvaloper1gp957czryfgyvxwn3tfnyy2f0t9g2p4ppzdrn6\",\"axelarvaloper1gsdk6eed465n0arjekwruwsfwyugasu55fdg7a\",\"axelarvaloper1gswfh889avkccdt5adqvglel9ttjglhdl0atqr\",\"axelarvaloper1gkjzwwk2jgqelgphu3fs5x7nd4sr08m5y78sse\",\"axelarvaloper1ge6g4tvutvr5ae6rhrh9sapqsyvyp3tku36p96\",\"axelarvaloper1f9laxzwy8u73jlutkg6qrj7yzkkwcjhvw6cf2v\",\"axelarvaloper12048f0g2qvm4xdru9knh7qqq4srr5lqxk53hfn\",\"axelarvaloper126yfkvn7lx280ccg2lnxty0n2ldzz6xnve3smx\",\"axelarvaloper1t58spqe28a7d8s2902ss90tet7q7e0rxzcyf63\",\"axelarvaloper1thl5syhmscgnj7whdyrydw3w6vy80044kf4tn2\",\"axelarvaloper1tee73c83k2vqky9gt59jd3ztwxhqjm27l588q6\",\"axelarvaloper1vq6rn6ph9hg3kf0l5lrvdnud9s46lp04mhhsk9\",\"axelarvaloper1d8j4hv0cd7sdgmta7l66g7hjuzu3f29chfkcvq\",\"axelarvaloper1ds9z59d9szmxlzt6f8f6l6sgaenxdyd6095gcg\",\"axelarvaloper1dkfwpeusuwya3lx7cayrlz5pr57r095w0t0674\",\"axelarvaloper1s2dnkgn4fg76esnkkpm08ac49j5zfl37f54vtr\",\"axelarvaloper1sdxevhsud70v2j9svgf4fx8203e80cqnexz8px\",\"axelarvaloper1s0lankh33kprer2l22nank5rvsuh9ksa6utflp\",\"axelarvaloper1sn4v8rp9j587uvrex4z9jw9frplv05vnxk92zs\",\"axelarvaloper1sm3mh5pxqlzx6swmf2dspcvnz3zw3ptycqtg3s\",\"axelarvaloper13877kqxl4gftkpjavd2kjjd0d9rfxcu53sq3z3\",\"axelarvaloper13s44uvtzf578zjze9eqeh0mnemj60pwn83frcp\",\"axelarvaloper13j0vglkah4c302pm9y0fr9qrue87d400tv7v57\",\"axelarvaloper137nzwehjcjxddsanmsmg29p729cm4dghj08clr\",\"axelarvaloper1j5vxzfx74xlml73e2mz9nn2ultz9jhzxjsakxw\",\"axelarvaloper1jmuwxehr35zducyv2er7duwk467j2mhmk3wry0\",\"axelarvaloper1nqe0ggecgsyaegl4t6m6k4786cd29xjt4znsf5\",\"axelarvaloper1nvsl9utkv0duhuvudjckvrtyfeyju0ygx3npw4\",\"axelarvaloper1n56swda49evz92zhcw2xc8esx6kzt8qmvfvgp6\",\"axelarvaloper148skr4d5vy6c9728zkf7cff9e5eykgwka3rvm7\",\"axelarvaloper14fpqu7kpvlhlhyefsmus6strrz4kwselc5caah\",\"axelarvaloper143f687gmeg2xjg2vr4lm9n796mt53eplv4qxgv\",\"axelarvaloper1kj8j6hkmgfvtxpgfuskj602sxs5dsfkm6ewm4l\",\"axelarvaloper1kkrp9ulfea5klffr7yjk0lat2yuxystgfzg6zu\",\"axelarvaloper1kafxdlrq8svz68j2tn8qtqk74j4yhylyf364pt\",\"axelarvaloper1hxlel3ank3229e5pc0ygku9vmjyuw8mku3a4s5\",\"axelarvaloper1et2clgngcx9s534akvk9p94p70jteas4vavakq\",\"axelarvaloper16pj5gljqnqs0ajxakccfjhu05yczp987zac7km\",\"axelarvaloper16nx30ear9ewsd9xuzy9wrlpp94vmdzlvq5jfdx\",\"axelarvaloper1uqe7c0d7uwdkslvv75nccxx74p09aqzhm7xs7c\",\"axelarvaloper1uf7s2v44qqpe9lpnsjy6cfjueqytakuzayfg0h\",\"axelarvaloper1uvx854yjzn9re8vu74067u68r4ar70tywgpcwg\",\"axelarvaloper1u3asfwr2q0xhshj88sq4yvh89qluunefh270lz\",\"axelarvaloper1ul27g47whcdtemrgyv80cxez7xw5xleg249wkt\",\"axelarvaloper1aatl2sl2ng5eygzjxx7ysn3jqd7dpr9n5shmmn\",\"axelarvaloper17q4fqv86dxkes384tnmrvjr9ljp2slunr6k00w\",\"axelarvaloper17eysfn7h36xlvl0kpe6c95f4w4hejr57raak27\",\"axelarvaloper17l9xc68m6stccpnj7d8dgy8ck62hqnzv9jfyg9\",\"axelarvaloper1l954fcz7hu9sedc7fd4ltjs4ucs7af6csqsxlw\"]}")
            ],
        );
        let event: event_sub::Event = event.into();
        let event: Result<evm_confirm_gateway_tx::Event, _> = match event {
            event_sub::Event::AbciEvent { event_type, attributes } if event_type.as_str() == EVENT_TYPE => {
                attributes.try_into()
            }
            _ => panic!("wrong type of event"),
        };
        assert!(event.is_ok());
    }

    #[test]
    fn deserialize_failed() {
        let event = abci::Event::new(
            "axelar.evm.v1beta1.ConfirmGatewayTxStarted",
            vec![
                // missing .chain
                ("gateway_address", "[79,68,149,36,56,55,104,16,97,196,116,59,116,179,238,223,84,141,86,165]"),
                ("tx_id", "[71,53,131,169,3,29,39,120,147,195,106,41,206,185,108,39,132,189,41,54,217,172,147,158,121,38,124,246,17,121,173,96]"),
                ("confirmation_height", "\"200\""),
                ("participants", "{\"poll_id\":\"41113\",\"participants\":[\"axelarvaloper1qy9uq03rkpqkzwsa4fz7xxetkxttdcj6tf09pg\",\"axelarvaloper1q2nyv5mwsu5r07x6djpgvm0jl9l9a5v88qllcd\",\"axelarvaloper1z9cz08mlfp6qz456zyzkw6epsjlzvr043m4rzz\",\"axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7\",\"axelarvaloper1zcsv9jp24nl0e4vha36l8dzypy363sw3rgq0zy\",\"axelarvaloper1rqp7vvl9cjmdan44dny56qadwg590uxv8hamux\",\"axelarvaloper1r7ppsrmzpslqu3d3yf344kzjv32n9dn4xyt0sw\",\"axelarvaloper1ypwzuhaffvr06ktu0ne6lnm69gxj32qwf94dg4\",\"axelarvaloper19ysyq74gkf8lv3l4suu3rlqadg4txp3sqxkhss\",\"axelarvaloper19dx6vywgr62jtsxhhlhlgh7ug5vmgjnz6dkeud\",\"axelarvaloper19wz0kfzj2czmjg9052h69wk6kgxc848hxs8rhl\",\"axelarvaloper1xy97mfxvm2qwtw7vt9e3m850eknxfwxd9l5ate\",\"axelarvaloper1x20lytyf6zkcrv5edpkfkn8sz578qg5s3j2wke\",\"axelarvaloper1xtawcxuvh3vtt6zht9pku3ltc0a76u209jl63x\",\"axelarvaloper1xesqr8vjvy34jhu027zd70ypl0nnev5ezjg5h9\",\"axelarvaloper18qydpumkn244ska4xw8890nc67l9e5qqm7c36r\",\"axelarvaloper186rt9fg3l6m9x2w9qxuvq80uapzhuezapyqser\",\"axelarvaloper1gp957czryfgyvxwn3tfnyy2f0t9g2p4ppzdrn6\",\"axelarvaloper1gsdk6eed465n0arjekwruwsfwyugasu55fdg7a\",\"axelarvaloper1gswfh889avkccdt5adqvglel9ttjglhdl0atqr\",\"axelarvaloper1gkjzwwk2jgqelgphu3fs5x7nd4sr08m5y78sse\",\"axelarvaloper1ge6g4tvutvr5ae6rhrh9sapqsyvyp3tku36p96\",\"axelarvaloper1f9laxzwy8u73jlutkg6qrj7yzkkwcjhvw6cf2v\",\"axelarvaloper12048f0g2qvm4xdru9knh7qqq4srr5lqxk53hfn\",\"axelarvaloper126yfkvn7lx280ccg2lnxty0n2ldzz6xnve3smx\",\"axelarvaloper1t58spqe28a7d8s2902ss90tet7q7e0rxzcyf63\",\"axelarvaloper1thl5syhmscgnj7whdyrydw3w6vy80044kf4tn2\",\"axelarvaloper1tee73c83k2vqky9gt59jd3ztwxhqjm27l588q6\",\"axelarvaloper1vq6rn6ph9hg3kf0l5lrvdnud9s46lp04mhhsk9\",\"axelarvaloper1d8j4hv0cd7sdgmta7l66g7hjuzu3f29chfkcvq\",\"axelarvaloper1ds9z59d9szmxlzt6f8f6l6sgaenxdyd6095gcg\",\"axelarvaloper1dkfwpeusuwya3lx7cayrlz5pr57r095w0t0674\",\"axelarvaloper1s2dnkgn4fg76esnkkpm08ac49j5zfl37f54vtr\",\"axelarvaloper1sdxevhsud70v2j9svgf4fx8203e80cqnexz8px\",\"axelarvaloper1s0lankh33kprer2l22nank5rvsuh9ksa6utflp\",\"axelarvaloper1sn4v8rp9j587uvrex4z9jw9frplv05vnxk92zs\",\"axelarvaloper1sm3mh5pxqlzx6swmf2dspcvnz3zw3ptycqtg3s\",\"axelarvaloper13877kqxl4gftkpjavd2kjjd0d9rfxcu53sq3z3\",\"axelarvaloper13s44uvtzf578zjze9eqeh0mnemj60pwn83frcp\",\"axelarvaloper13j0vglkah4c302pm9y0fr9qrue87d400tv7v57\",\"axelarvaloper137nzwehjcjxddsanmsmg29p729cm4dghj08clr\",\"axelarvaloper1j5vxzfx74xlml73e2mz9nn2ultz9jhzxjsakxw\",\"axelarvaloper1jmuwxehr35zducyv2er7duwk467j2mhmk3wry0\",\"axelarvaloper1nqe0ggecgsyaegl4t6m6k4786cd29xjt4znsf5\",\"axelarvaloper1nvsl9utkv0duhuvudjckvrtyfeyju0ygx3npw4\",\"axelarvaloper1n56swda49evz92zhcw2xc8esx6kzt8qmvfvgp6\",\"axelarvaloper148skr4d5vy6c9728zkf7cff9e5eykgwka3rvm7\",\"axelarvaloper14fpqu7kpvlhlhyefsmus6strrz4kwselc5caah\",\"axelarvaloper143f687gmeg2xjg2vr4lm9n796mt53eplv4qxgv\",\"axelarvaloper1kj8j6hkmgfvtxpgfuskj602sxs5dsfkm6ewm4l\",\"axelarvaloper1kkrp9ulfea5klffr7yjk0lat2yuxystgfzg6zu\",\"axelarvaloper1kafxdlrq8svz68j2tn8qtqk74j4yhylyf364pt\",\"axelarvaloper1hxlel3ank3229e5pc0ygku9vmjyuw8mku3a4s5\",\"axelarvaloper1et2clgngcx9s534akvk9p94p70jteas4vavakq\",\"axelarvaloper16pj5gljqnqs0ajxakccfjhu05yczp987zac7km\",\"axelarvaloper16nx30ear9ewsd9xuzy9wrlpp94vmdzlvq5jfdx\",\"axelarvaloper1uqe7c0d7uwdkslvv75nccxx74p09aqzhm7xs7c\",\"axelarvaloper1uf7s2v44qqpe9lpnsjy6cfjueqytakuzayfg0h\",\"axelarvaloper1uvx854yjzn9re8vu74067u68r4ar70tywgpcwg\",\"axelarvaloper1u3asfwr2q0xhshj88sq4yvh89qluunefh270lz\",\"axelarvaloper1ul27g47whcdtemrgyv80cxez7xw5xleg249wkt\",\"axelarvaloper1aatl2sl2ng5eygzjxx7ysn3jqd7dpr9n5shmmn\",\"axelarvaloper17q4fqv86dxkes384tnmrvjr9ljp2slunr6k00w\",\"axelarvaloper17eysfn7h36xlvl0kpe6c95f4w4hejr57raak27\",\"axelarvaloper17l9xc68m6stccpnj7d8dgy8ck62hqnzv9jfyg9\",\"axelarvaloper1l954fcz7hu9sedc7fd4ltjs4ucs7af6csqsxlw\"]}")
            ],
        );
        let event: event_sub::Event = event.into();
        let event: Result<evm_confirm_gateway_tx::Event, _> = match event {
            event_sub::Event::AbciEvent { event_type, attributes } if event_type.as_str() == EVENT_TYPE => {
                attributes.try_into()
            }
            _ => panic!("wrong type of event"),
        };
        assert!(event.is_err());

        let event = abci::Event::new(
                "axelar.evm.v1beta1.ConfirmGatewayTxStarted",
                vec![
                    ("chain", "\"Ethereum\""),
                    ("gateway_address", "[79,68,149,36,56,55,104,16,97,196,116,59,116,179,238,223,84,141,86,165,111]"), // invalid
                    ("tx_id", "[71,53,131,169,3,29,39,120,147,195,106,41,206,185,108,39,132,189,41,54,217,172,147,158,121,38,124,246,17,121,173,96]"),
                    ("confirmation_height", "\"200\""),
                    ("participants", "{\"poll_id\":\"41113\",\"participants\":[\"axelarvaloper1qy9uq03rkpqkzwsa4fz7xxetkxttdcj6tf09pg\",\"axelarvaloper1q2nyv5mwsu5r07x6djpgvm0jl9l9a5v88qllcd\",\"axelarvaloper1z9cz08mlfp6qz456zyzkw6epsjlzvr043m4rzz\",\"axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7\",\"axelarvaloper1zcsv9jp24nl0e4vha36l8dzypy363sw3rgq0zy\",\"axelarvaloper1rqp7vvl9cjmdan44dny56qadwg590uxv8hamux\",\"axelarvaloper1r7ppsrmzpslqu3d3yf344kzjv32n9dn4xyt0sw\",\"axelarvaloper1ypwzuhaffvr06ktu0ne6lnm69gxj32qwf94dg4\",\"axelarvaloper19ysyq74gkf8lv3l4suu3rlqadg4txp3sqxkhss\",\"axelarvaloper19dx6vywgr62jtsxhhlhlgh7ug5vmgjnz6dkeud\",\"axelarvaloper19wz0kfzj2czmjg9052h69wk6kgxc848hxs8rhl\",\"axelarvaloper1xy97mfxvm2qwtw7vt9e3m850eknxfwxd9l5ate\",\"axelarvaloper1x20lytyf6zkcrv5edpkfkn8sz578qg5s3j2wke\",\"axelarvaloper1xtawcxuvh3vtt6zht9pku3ltc0a76u209jl63x\",\"axelarvaloper1xesqr8vjvy34jhu027zd70ypl0nnev5ezjg5h9\",\"axelarvaloper18qydpumkn244ska4xw8890nc67l9e5qqm7c36r\",\"axelarvaloper186rt9fg3l6m9x2w9qxuvq80uapzhuezapyqser\",\"axelarvaloper1gp957czryfgyvxwn3tfnyy2f0t9g2p4ppzdrn6\",\"axelarvaloper1gsdk6eed465n0arjekwruwsfwyugasu55fdg7a\",\"axelarvaloper1gswfh889avkccdt5adqvglel9ttjglhdl0atqr\",\"axelarvaloper1gkjzwwk2jgqelgphu3fs5x7nd4sr08m5y78sse\",\"axelarvaloper1ge6g4tvutvr5ae6rhrh9sapqsyvyp3tku36p96\",\"axelarvaloper1f9laxzwy8u73jlutkg6qrj7yzkkwcjhvw6cf2v\",\"axelarvaloper12048f0g2qvm4xdru9knh7qqq4srr5lqxk53hfn\",\"axelarvaloper126yfkvn7lx280ccg2lnxty0n2ldzz6xnve3smx\",\"axelarvaloper1t58spqe28a7d8s2902ss90tet7q7e0rxzcyf63\",\"axelarvaloper1thl5syhmscgnj7whdyrydw3w6vy80044kf4tn2\",\"axelarvaloper1tee73c83k2vqky9gt59jd3ztwxhqjm27l588q6\",\"axelarvaloper1vq6rn6ph9hg3kf0l5lrvdnud9s46lp04mhhsk9\",\"axelarvaloper1d8j4hv0cd7sdgmta7l66g7hjuzu3f29chfkcvq\",\"axelarvaloper1ds9z59d9szmxlzt6f8f6l6sgaenxdyd6095gcg\",\"axelarvaloper1dkfwpeusuwya3lx7cayrlz5pr57r095w0t0674\",\"axelarvaloper1s2dnkgn4fg76esnkkpm08ac49j5zfl37f54vtr\",\"axelarvaloper1sdxevhsud70v2j9svgf4fx8203e80cqnexz8px\",\"axelarvaloper1s0lankh33kprer2l22nank5rvsuh9ksa6utflp\",\"axelarvaloper1sn4v8rp9j587uvrex4z9jw9frplv05vnxk92zs\",\"axelarvaloper1sm3mh5pxqlzx6swmf2dspcvnz3zw3ptycqtg3s\",\"axelarvaloper13877kqxl4gftkpjavd2kjjd0d9rfxcu53sq3z3\",\"axelarvaloper13s44uvtzf578zjze9eqeh0mnemj60pwn83frcp\",\"axelarvaloper13j0vglkah4c302pm9y0fr9qrue87d400tv7v57\",\"axelarvaloper137nzwehjcjxddsanmsmg29p729cm4dghj08clr\",\"axelarvaloper1j5vxzfx74xlml73e2mz9nn2ultz9jhzxjsakxw\",\"axelarvaloper1jmuwxehr35zducyv2er7duwk467j2mhmk3wry0\",\"axelarvaloper1nqe0ggecgsyaegl4t6m6k4786cd29xjt4znsf5\",\"axelarvaloper1nvsl9utkv0duhuvudjckvrtyfeyju0ygx3npw4\",\"axelarvaloper1n56swda49evz92zhcw2xc8esx6kzt8qmvfvgp6\",\"axelarvaloper148skr4d5vy6c9728zkf7cff9e5eykgwka3rvm7\",\"axelarvaloper14fpqu7kpvlhlhyefsmus6strrz4kwselc5caah\",\"axelarvaloper143f687gmeg2xjg2vr4lm9n796mt53eplv4qxgv\",\"axelarvaloper1kj8j6hkmgfvtxpgfuskj602sxs5dsfkm6ewm4l\",\"axelarvaloper1kkrp9ulfea5klffr7yjk0lat2yuxystgfzg6zu\",\"axelarvaloper1kafxdlrq8svz68j2tn8qtqk74j4yhylyf364pt\",\"axelarvaloper1hxlel3ank3229e5pc0ygku9vmjyuw8mku3a4s5\",\"axelarvaloper1et2clgngcx9s534akvk9p94p70jteas4vavakq\",\"axelarvaloper16pj5gljqnqs0ajxakccfjhu05yczp987zac7km\",\"axelarvaloper16nx30ear9ewsd9xuzy9wrlpp94vmdzlvq5jfdx\",\"axelarvaloper1uqe7c0d7uwdkslvv75nccxx74p09aqzhm7xs7c\",\"axelarvaloper1uf7s2v44qqpe9lpnsjy6cfjueqytakuzayfg0h\",\"axelarvaloper1uvx854yjzn9re8vu74067u68r4ar70tywgpcwg\",\"axelarvaloper1u3asfwr2q0xhshj88sq4yvh89qluunefh270lz\",\"axelarvaloper1ul27g47whcdtemrgyv80cxez7xw5xleg249wkt\",\"axelarvaloper1aatl2sl2ng5eygzjxx7ysn3jqd7dpr9n5shmmn\",\"axelarvaloper17q4fqv86dxkes384tnmrvjr9ljp2slunr6k00w\",\"axelarvaloper17eysfn7h36xlvl0kpe6c95f4w4hejr57raak27\",\"axelarvaloper17l9xc68m6stccpnj7d8dgy8ck62hqnzv9jfyg9\",\"axelarvaloper1l954fcz7hu9sedc7fd4ltjs4ucs7af6csqsxlw\"]}")
                ],
            );
        let event: event_sub::Event = event.into();
        let event: Result<evm_confirm_gateway_tx::Event, _> = match event {
            event_sub::Event::AbciEvent { event_type, attributes } if event_type.as_str() == EVENT_TYPE => {
                attributes.try_into()
            }
            _ => panic!("wrong type of event"),
        };
        assert!(event.is_err());

        let event = abci::Event::new(
                "axelar.evm.v1beta1.ConfirmGatewayTxStarted",
                vec![
                    ("chain", "\"Ethereum\""),
                    ("gateway_address", "[79,68,149,36,56,55,104,16,97,196,116,59,116,179,238,223,84,141,86,165]"),
                    ("tx_id", "[71,53,131,169,3,29,39,120,147,195,106,41,206,185,108,39,132,189,41,54,217,172,147,158,121,38,124,246,17,121,173,96,100]"), // invalid
                    ("confirmation_height", "\"200\""),
                    ("participants", "{\"poll_id\":\"41113\",\"participants\":[\"axelarvaloper1qy9uq03rkpqkzwsa4fz7xxetkxttdcj6tf09pg\",\"axelarvaloper1q2nyv5mwsu5r07x6djpgvm0jl9l9a5v88qllcd\",\"axelarvaloper1z9cz08mlfp6qz456zyzkw6epsjlzvr043m4rzz\",\"axelarvaloper1zh9wrak6ke4n6fclj5e8yk397czv430ygs5jz7\",\"axelarvaloper1zcsv9jp24nl0e4vha36l8dzypy363sw3rgq0zy\",\"axelarvaloper1rqp7vvl9cjmdan44dny56qadwg590uxv8hamux\",\"axelarvaloper1r7ppsrmzpslqu3d3yf344kzjv32n9dn4xyt0sw\",\"axelarvaloper1ypwzuhaffvr06ktu0ne6lnm69gxj32qwf94dg4\",\"axelarvaloper19ysyq74gkf8lv3l4suu3rlqadg4txp3sqxkhss\",\"axelarvaloper19dx6vywgr62jtsxhhlhlgh7ug5vmgjnz6dkeud\",\"axelarvaloper19wz0kfzj2czmjg9052h69wk6kgxc848hxs8rhl\",\"axelarvaloper1xy97mfxvm2qwtw7vt9e3m850eknxfwxd9l5ate\",\"axelarvaloper1x20lytyf6zkcrv5edpkfkn8sz578qg5s3j2wke\",\"axelarvaloper1xtawcxuvh3vtt6zht9pku3ltc0a76u209jl63x\",\"axelarvaloper1xesqr8vjvy34jhu027zd70ypl0nnev5ezjg5h9\",\"axelarvaloper18qydpumkn244ska4xw8890nc67l9e5qqm7c36r\",\"axelarvaloper186rt9fg3l6m9x2w9qxuvq80uapzhuezapyqser\",\"axelarvaloper1gp957czryfgyvxwn3tfnyy2f0t9g2p4ppzdrn6\",\"axelarvaloper1gsdk6eed465n0arjekwruwsfwyugasu55fdg7a\",\"axelarvaloper1gswfh889avkccdt5adqvglel9ttjglhdl0atqr\",\"axelarvaloper1gkjzwwk2jgqelgphu3fs5x7nd4sr08m5y78sse\",\"axelarvaloper1ge6g4tvutvr5ae6rhrh9sapqsyvyp3tku36p96\",\"axelarvaloper1f9laxzwy8u73jlutkg6qrj7yzkkwcjhvw6cf2v\",\"axelarvaloper12048f0g2qvm4xdru9knh7qqq4srr5lqxk53hfn\",\"axelarvaloper126yfkvn7lx280ccg2lnxty0n2ldzz6xnve3smx\",\"axelarvaloper1t58spqe28a7d8s2902ss90tet7q7e0rxzcyf63\",\"axelarvaloper1thl5syhmscgnj7whdyrydw3w6vy80044kf4tn2\",\"axelarvaloper1tee73c83k2vqky9gt59jd3ztwxhqjm27l588q6\",\"axelarvaloper1vq6rn6ph9hg3kf0l5lrvdnud9s46lp04mhhsk9\",\"axelarvaloper1d8j4hv0cd7sdgmta7l66g7hjuzu3f29chfkcvq\",\"axelarvaloper1ds9z59d9szmxlzt6f8f6l6sgaenxdyd6095gcg\",\"axelarvaloper1dkfwpeusuwya3lx7cayrlz5pr57r095w0t0674\",\"axelarvaloper1s2dnkgn4fg76esnkkpm08ac49j5zfl37f54vtr\",\"axelarvaloper1sdxevhsud70v2j9svgf4fx8203e80cqnexz8px\",\"axelarvaloper1s0lankh33kprer2l22nank5rvsuh9ksa6utflp\",\"axelarvaloper1sn4v8rp9j587uvrex4z9jw9frplv05vnxk92zs\",\"axelarvaloper1sm3mh5pxqlzx6swmf2dspcvnz3zw3ptycqtg3s\",\"axelarvaloper13877kqxl4gftkpjavd2kjjd0d9rfxcu53sq3z3\",\"axelarvaloper13s44uvtzf578zjze9eqeh0mnemj60pwn83frcp\",\"axelarvaloper13j0vglkah4c302pm9y0fr9qrue87d400tv7v57\",\"axelarvaloper137nzwehjcjxddsanmsmg29p729cm4dghj08clr\",\"axelarvaloper1j5vxzfx74xlml73e2mz9nn2ultz9jhzxjsakxw\",\"axelarvaloper1jmuwxehr35zducyv2er7duwk467j2mhmk3wry0\",\"axelarvaloper1nqe0ggecgsyaegl4t6m6k4786cd29xjt4znsf5\",\"axelarvaloper1nvsl9utkv0duhuvudjckvrtyfeyju0ygx3npw4\",\"axelarvaloper1n56swda49evz92zhcw2xc8esx6kzt8qmvfvgp6\",\"axelarvaloper148skr4d5vy6c9728zkf7cff9e5eykgwka3rvm7\",\"axelarvaloper14fpqu7kpvlhlhyefsmus6strrz4kwselc5caah\",\"axelarvaloper143f687gmeg2xjg2vr4lm9n796mt53eplv4qxgv\",\"axelarvaloper1kj8j6hkmgfvtxpgfuskj602sxs5dsfkm6ewm4l\",\"axelarvaloper1kkrp9ulfea5klffr7yjk0lat2yuxystgfzg6zu\",\"axelarvaloper1kafxdlrq8svz68j2tn8qtqk74j4yhylyf364pt\",\"axelarvaloper1hxlel3ank3229e5pc0ygku9vmjyuw8mku3a4s5\",\"axelarvaloper1et2clgngcx9s534akvk9p94p70jteas4vavakq\",\"axelarvaloper16pj5gljqnqs0ajxakccfjhu05yczp987zac7km\",\"axelarvaloper16nx30ear9ewsd9xuzy9wrlpp94vmdzlvq5jfdx\",\"axelarvaloper1uqe7c0d7uwdkslvv75nccxx74p09aqzhm7xs7c\",\"axelarvaloper1uf7s2v44qqpe9lpnsjy6cfjueqytakuzayfg0h\",\"axelarvaloper1uvx854yjzn9re8vu74067u68r4ar70tywgpcwg\",\"axelarvaloper1u3asfwr2q0xhshj88sq4yvh89qluunefh270lz\",\"axelarvaloper1ul27g47whcdtemrgyv80cxez7xw5xleg249wkt\",\"axelarvaloper1aatl2sl2ng5eygzjxx7ysn3jqd7dpr9n5shmmn\",\"axelarvaloper17q4fqv86dxkes384tnmrvjr9ljp2slunr6k00w\",\"axelarvaloper17eysfn7h36xlvl0kpe6c95f4w4hejr57raak27\",\"axelarvaloper17l9xc68m6stccpnj7d8dgy8ck62hqnzv9jfyg9\",\"axelarvaloper1l954fcz7hu9sedc7fd4ltjs4ucs7af6csqsxlw\"]}")
                ],
            );
        let event: event_sub::Event = event.into();
        let event: Result<evm_confirm_gateway_tx::Event, _> = match event {
            event_sub::Event::AbciEvent { event_type, attributes } if event_type.as_str() == EVENT_TYPE => {
                attributes.try_into()
            }
            _ => panic!("wrong type of event"),
        };
        assert!(event.is_err());

        let event = abci::Event::new(
            "axelar.evm.v1beta1.ConfirmGatewayTxStarted",
            vec![
                    ("chain", "\"Ethereum\""),
                    ("gateway_address", "[79,68,149,36,56,55,104,16,97,196,116,59,116,179,238,223,84,141,86,165]"),
                    ("tx_id", "[71,53,131,169,3,29,39,120,147,195,106,41,206,185,108,39,132,189,41,54,217,172,147,158,121,38,124,246,17,121,173,96]"),
                    ("confirmation_height", "\"200\""),
                    ("participants", "{\"poll_id\":\"41113\",\"participants\":[\"axelarvaloper1qy9uq03rkpqkzwsa4fz7xxetkxttdcj6tf09p\"]}") // invalid
                ],
        );
        let event: event_sub::Event = event.into();
        let event: Result<evm_confirm_gateway_tx::Event, _> = match event {
            event_sub::Event::AbciEvent { event_type, attributes } if event_type.as_str() == EVENT_TYPE => {
                attributes.try_into()
            }
            _ => panic!("wrong type of event"),
        };
        assert!(event.is_err());
    }
}
