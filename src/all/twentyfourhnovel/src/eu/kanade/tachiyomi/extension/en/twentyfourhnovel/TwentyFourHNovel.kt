package eu.kanade.tachiyomi.extension.en.twentyfourhnovel

import eu.kanade.tachiyomi.source.SourceFactory
import eu.kanade.tachiyomi.source.online.HttpSource
import eu.kanade.tachiyomi.source.model.FilterList
import okhttp3.Response

class TwentyFourHNovel : SourceFactory {

    override fun createSources() = listOf(
        TwentyFourHNovelSource()
    )
}

class TwentyFourHNovelSource : HttpSource() {

    override val name = "24hNovel"
    override val baseUrl = "https://24hnovel.com"
    override val lang = "en"
    override val supportsLatest = false

    override fun popularMangaRequest() =
        throw UnsupportedOperationException()

    override fun popularMangaParse(response: Response) =
        throw UnsupportedOperationException()

    override fun latestUpdatesRequest() =
        throw UnsupportedOperationException()

    override fun latestUpdatesParse(response: Response) =
        throw UnsupportedOperationException()

    override fun searchMangaRequest(
        page: Int,
        query: String,
        filters: FilterList
    ) =
        throw UnsupportedOperationException()

    override fun searchMangaParse(response: Response) =
        throw UnsupportedOperationException()

    override fun mangaDetailsParse(response: Response) =
        throw UnsupportedOperationException()

    override fun chapterListParse(response: Response) =
        throw UnsupportedOperationException()

    override fun pageListParse(response: Response) =
        throw UnsupportedOperationException()

    override fun imageUrlParse(response: Response) =
        throw UnsupportedOperationException()
}
