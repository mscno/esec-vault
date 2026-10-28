import AppKit
import EsecVaultCore
import SwiftUI

enum Selection: Hashable {
    case health
    case project(String)
}

struct MainView: View {
    @Environment(Store.self) private var store
    @State private var selection: Selection? = .health

    var body: some View {
        @Bindable var store = store
        NavigationSplitView {
            List(selection: $selection) {
                Label {
                    Text("Key Health")
                } icon: {
                    Image(systemName: store.health.symbol).foregroundStyle(store.health.color)
                }
                .tag(Selection.health)
                ForEach(store.namespaces, id: \.name) { group in
                    Section(group.name) {
                        ForEach(group.projects) { p in
                            ProjectRow(project: p).tag(Selection.project(p.project))
                        }
                    }
                }
            }
            .searchable(text: $store.search, placement: .sidebar, prompt: "Projects and paths")
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            .overlay {
                if store.projects.isEmpty, store.lastError == nil {
                    ContentUnavailableView("No projects yet", systemImage: "folder.badge.questionmark",
                                           description: Text("Find your checkouts: File › Find Checkouts…"))
                }
            }
        } detail: {
            switch selection {
            case let .project(id):
                ProjectDetail(id: id)
            default:
                HealthView()
            }
        }
        .toolbar {
            ToolbarItemGroup {
                if let busy = store.busy {
                    ProgressView().controlSize(.small)
                    Text(busy).foregroundStyle(.secondary)
                }
                Button { pickFolder(scan: true) } label: { Label("Find Checkouts", systemImage: "magnifyingglass") }
                    .help("Find every checkout (a folder with esec.toml) under a folder, such as ~/src")
                Button { pickFolder(scan: false) } label: { Label("Add Checkout", systemImage: "plus") }
                    .help("Remember one checkout")
                Button { Task { await store.refresh() } } label: { Label("Refresh", systemImage: "arrow.clockwise") }
            }
        }
        .safeAreaInset(edge: .bottom) {
            if let err = store.lastError {
                Banner(text: err, systemImage: "exclamationmark.triangle.fill", tint: .orange) { store.lastError = nil }
            } else if let msg = store.message {
                Banner(text: msg, systemImage: "checkmark.circle.fill", tint: .green) { store.message = nil }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .scanFolder)) { _ in pickFolder(scan: true) }
    }

    private func pickFolder(scan: Bool) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = scan ? "Find Checkouts" : "Add"
        panel.message = scan ? "Every folder with an esec.toml below this one is remembered." : "Choose a folder with an esec.toml."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { scan ? await store.scan(url) : await store.add(url) }
    }
}

struct ProjectRow: View {
    let project: Project

    var body: some View {
        HStack {
            Text(project.name)
            Spacer()
            if project.envs.contains(where: \.isGuarded) {
                Image(systemName: "lock.fill").foregroundStyle(.secondary).help("Has guarded environments")
            }
            if project.hasProblem {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
        }
    }
}

struct Banner: View {
    let text: String
    let systemImage: String
    let tint: Color
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .top) {
            Image(systemName: systemImage).foregroundStyle(tint)
            Text(text).textSelection(.enabled).lineLimit(3)
            Spacer()
            Button("Dismiss", action: dismiss).buttonStyle(.borderless)
        }
        .padding(10)
        .background(.bar)
    }
}
