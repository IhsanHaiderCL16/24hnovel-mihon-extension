package eu.kanade.tachiyomi.extension.all.twentyfourhnovel

import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.ParsedHttpSource
import okhttp3.Request
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element

class TwentyFourHNovel : ParsedHttpSource() {

    override val name = "24hNovel"
    override val baseUrl = "https://24hnovel.com"
    override val lang = "en"
    override val supportsLatest = false

    // ============================== Popular ==============================

    override fun popularMangaRequest(page: Int): Request {
        return GET("$baseUrl/manga/page/$page/")
    }

    override fun popularMangaSelector(): String = "div.page-item-detail"

    override fun popularMangaFromElement(element: Element): SManga {
        return SManga.create().apply {
            title = element.select("h3 a").text()
            url = element.select("h3 a").attr("href")
            thumbnail_url = element.select("img").attr("src")
        }
    }

    override fun popularMangaNextPageSelector(): String =
        "a.next"

    // ============================== Search ==============================

    override fun searchMangaRequest(page: Int, query: String, filters: FilterList): Request {
        return GET("$baseUrl/?s=$query&post_type=wp-manga")
    }

    override fun searchMangaSelector(): String = popularMangaSelector()
    override fun searchMangaFromElement(element: Element): SManga =
        popularMangaFromElement(element)

    override fun searchMangaNextPageSelector(): String? = null

    // ============================== Manga Details ==============================

    override fun mangaDetailsParse(document: Document): SManga {
        return SManga.create().apply {
            title = document.selectFirst("h1")?.text() ?: ""
            description = document.select("div.description-summary").text()
            genre = document.select("div.genres a").joinToString { it.text() }
            status = SManga.UNKNOWN
        }
    }

    // ============================== Chapters ==============================

    override fun chapterListSelector(): String =
        "li.wp-manga-chapter"

    override fun chapterFromElement(element: Element): SChapter {
        return SChapter.create().apply {
            name = element.select("a").text()
            url = element.select("a").attr("href")
        }
    }

    override fun chapterListParse(response: okhttp3.Response): List<SChapter> {
        return super.chapterListParse(response).reversed()
    }

    // ============================== Pages ==============================

    override fun pageListParse(document: Document): List<Page> {
        return document.select("div.reading-content img").mapIndexed { index, img ->
            Page(index, imageUrl = img.attr("src"))
        }
    }

    override fun imageUrlParse(document: Document): String = ""
}
