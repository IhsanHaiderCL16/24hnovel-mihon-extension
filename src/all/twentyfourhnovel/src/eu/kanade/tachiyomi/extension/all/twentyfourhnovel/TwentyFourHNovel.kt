package eu.kanade.tachiyomi.extension.all.twentyfourhnovel

import eu.kanade.tachiyomi.source.SourceFactory
import eu.kanade.tachiyomi.source.online.HttpSource

class TwentyFourHNovel : SourceFactory {

    override fun createSources() = listOf(TwentyFourHNovelSource())
}

class TwentyFourHNovelSource : HttpSource() {

    override val name = "24hNovel"
    override val baseUrl = "https://24hnovel.com"
    override val lang = "en"
    override val supportsLatest = false

    override fun popularMangaRequest() = throw UnsupportedOperationException()
    override fun popularMangaParse(response: okhttp3.Response) =
        throw UnsupportedOperationException()

    override fun latestUpdatesRequest() = throw UnsupportedOperationException()
    override fun latestUpdatesParse(response: okhttp3.Response) =
        throw UnsupportedOperationException()

    override fun searchMangaRequest(
        page: Int,
        query: String,
        filters: eu.kanade.tachiyomi.source.model.FilterList
    ) = throw UnsupportedOperationException()

    override fun searchMangaParse(response: okhttp3.Response) =
        throw UnsupportedOperationException()

    override fun mangaDetailsParse(response: okhttp3.Response) =
        throw UnsupportedOperationException()

    override fun chapterListParse(response: okhttp3.Response) =
        throw UnsupportedOperationException()

    override fun pageListParse(response: okhttp3.Response) =
        throw UnsupportedOperationException()

    override fun imageUrlParse(response: okhttp3.Response) =
        throw UnsupportedOperationException()
}
