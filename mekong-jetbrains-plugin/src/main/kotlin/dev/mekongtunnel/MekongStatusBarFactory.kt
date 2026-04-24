package dev.mekongtunnel

import com.intellij.ide.BrowserUtil
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory
import com.intellij.util.Consumer
import java.awt.event.MouseEvent

class MekongStatusBarFactory : StatusBarWidgetFactory {
    override fun getId()           = "MekongStatusBar"
    override fun getDisplayName()  = "Mekong Tunnel"
    override fun isAvailable(p: Project) = true
    override fun createWidget(project: Project) = MekongStatusBarWidget()
    override fun disposeWidget(widget: StatusBarWidget) = widget.dispose()
    override fun canBeEnabledOn(statusBar: StatusBar) = true
}

class MekongStatusBarWidget : StatusBarWidget, StatusBarWidget.TextPresentation {

    private val svc = MekongService.getInstance()
    private var bar: StatusBar? = null

    override fun ID() = "MekongStatusBar"

    override fun getPresentation(): StatusBarWidget.WidgetPresentation = this

    override fun install(statusBar: StatusBar) {
        bar = statusBar
        svc.addListener { statusBar.updateWidget(ID()) }
    }

    override fun dispose() { bar = null }

    override fun getText(): String {
        val url = svc.publicUrl
        return when {
            svc.isRunning && url != null -> "⚡ ${url.removePrefix("https://").removePrefix("http://")}"
            svc.isRunning               -> "⚡ Mekong: connecting…"
            svc.isLiveRunning           -> "⚡ Live :${svc.livePort}"
            else                        -> "⚡ Mekong"
        }
    }

    override fun getTooltipText() = when {
        svc.isRunning && svc.publicUrl != null -> "Tunnel active: ${svc.publicUrl} — click to open"
        svc.isRunning   -> "Tunnel connecting…"
        svc.isLiveRunning -> "Live Server on http://localhost:${svc.livePort} — click to open"
        else -> "Mekong Tunnel — click to open panel"
    }

    override fun getClickConsumer() = Consumer<MouseEvent> {
        val url = svc.publicUrl
        if (url != null) BrowserUtil.browse(url)
        else if (svc.isLiveRunning && svc.livePort != null) BrowserUtil.browse("http://localhost:${svc.livePort}")
    }

    override fun getAlignment() = 0f
}
