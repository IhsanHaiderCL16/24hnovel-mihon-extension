package eu.kanade.tachiyomi.extension.all.twentyfourhnovel

import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.ParsedHttpSource
import okhttp3.Request
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element

class TwentyFourHNovel : ParsedHttpSource() {

    override val name = "24HNovel"

    override val baseUrl = "https://24hnovel.com"

    override val lang = "en"

    override val supportsLatest = true

    /* ============================== Popular ============================== */

    override fun popularMangaRequest(page: Int): Request {
        return GET("$baseUrl/novel-list/?page=$page")
    }

    override fun popularMangaSelector(): String {
        return "div.listupd > div.bs"
    }

    override fun popularMangaFromElement(element: Element): SManga {
        return SManga.create().apply {
            title = element.selectFirst("a")!!.attr("title")
            url = element.selectFirst("a")!!.attr("href")
            thumbnail_url = element.selectFirst("img")?.attr("data-src")
        }
    }

    override fun popularMangaNextPageSelector(): String {
        return "a.next"
    }

    /* ============================== Latest ============================== */

    override fun latestUpdatesRequest(page: Int): Request {
        return GET("$baseUrl/latest/?page=$page")
    }

    override fun latestUpdatesSelector(): String {
        return popularMangaSelector()
    }

    override fun latestUpdatesFromElement(element: Element): SManga {
        return popularMangaFromElement(element)
    }

    override fun latestUpdatesNextPageSelector(): String {
        return popularMangaNextPageSelector()
    }

    /* ============================== Search ============================== */

    override fun searchMangaRequest(page: Int, query: String, filters: FilterList): Request {
        return GET("$baseUrl/?s=$query&page=$page")
    }

    override fun searchMangaSelector(): String {
        return popularMangaSelector()
    }

    override fun searchMangaFromElement(element: Element): SManga {
        return popularMangaFromElement(element)
    }

    override fun searchMangaNextPageSelector(): String {
        return popularMangaNextPageSelector()
    }

    /* ============================== Details ============================== */

    override fun mangaDetailsParse(document: Document): SManga {
        return SManga.create().apply {
            title = document.selectFirst("h1")!!.text()
            author = document.select("div.author-content a").joinToString { it.text() }
            genre = document.select("div.genres-content a").joinToString { it.text() }
            description = document.selectFirst("div.description-summary")?.text()
            thumbnail_url = document.selectFirst("div.thumb img")?.attr("src")
            status = SManga.UNKNOWN
        }
    }

    /* ============================== Chapters ============================== */

    override fun chapterListSelector(): String {
        return "ul.chapter-list li"
    }

    override fun chapterFromElement(element: Element): SChapter {
        return SChapter.create().apply {
            name = element.selectFirst("a")!!.text()
            url = element.selectFirst("a")!!.attr("href")
        }
    }

    /* ============================== Pages ============================== */

    override fun pageListParse(document: Document): List<Page> {
        val content = document.selectFirst("div.text-left") ?: return emptyList()
        return content.select("p").mapIndexed { index, _ ->
            Page(index, "")
        }
    }

    override fun imageUrlParse(document: Document): String {
        throw UnsupportedOperationException("Not used for text sources")
    }
}
