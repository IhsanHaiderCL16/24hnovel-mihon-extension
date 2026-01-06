package eu.kanade.tachiyomi.extension.all.twentyfourhnovel

import eu.kanade.tachiyomi.multisrc.madara.Madara

class TwentyFourHNovel : Madara(
    name = "24hNovel",
    baseUrl = "https://24hnovel.com",
    lang = "en",
) {
    override val useNewChapterEndpoint = true
}
