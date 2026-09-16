
const specURL = {
    "localhost:9000":       "a8ejpredirect",
    "px.a8.net":            "a8ejpredirect",
    "hb.afl.rakuten.co.jp": "pc",
}

var commonParams = ["url", "redirect", "jump",]


exports.handler =  async function(event, context) {

    
    return context.logStreamName
}