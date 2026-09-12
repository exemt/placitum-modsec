/*
 * Выбор профиля правил по маршруту и его атомарная подмена при обновлении.
 *
 * Профиль выбирается по явному тегу route.profile из сообщения, а не угадыванием
 * по route.server_name/route.location: карта маршрутов nginx живёт в
 * конфигурации nginx и второй копии здесь не заводится.
 */

package rules

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"

	"github.com/exemt/placitum-modsec/internal/config"
	"github.com/exemt/placitum-modsec/internal/engine"
	corazaengine "github.com/exemt/placitum-modsec/internal/engine/coraza"
	"github.com/exemt/placitum-modsec/internal/prior"
)

// DefaultProfile обязателен и проверяется при старте процесса: без него откат
// по политике default был бы отказом самого инспектора, а не находкой в
// конфигурации маршрута.
const DefaultProfile = "default"

/*
 * Подкаталог набора. Набор один на всю транзакцию HTTP -- фазы 1-5, обе
 * стороны: транзакция живёт весь запрос, и фазы 3-4 доигрываются поверх
 * состояния фаз 1-2. Разделять наборы по фазам значило бы держать две копии
 * CRS и терять между ними контекст запроса, ради которого правила ответа и
 * пишутся.
 *
 * Уровень при этом остаётся: он и переименовывается вместе со смыслом. Кадры
 * -- не транзакция HTTP, у них будет свой набор и свой подкаталог, а раздача
 * конфигурации (internal/desired) подменяет каталог целиком, и подменять ей
 * нужно что-то одно.
 */
const TreeDir = "http"

/*
 * Правила CRS включаются из встроенной файловой системы coraza-coreruleset, а
 * локальные файлы профиля читаются с диска. Парсер SecLang умеет работать
 * только с одним корнем, поэтому корни объединяются: пути с "@" разрешает
 * встроенный набор, все остальные -- обычная файловая система.
 */
var root fs.FS = mergefs.Merge(coreruleset.FS, mergefsio.OSFS)

// Set -- неизменяемый снимок всех профилей. Подменяется целиком: собрать,
// проверить, подставить указатель. Старый снимок доживает до завершения
// транзакций, которые его уже взяли.
type Set struct {
	profiles map[string]profile
}

// profile -- набор правил движка и правила приёма чужих действий. Живут
// вместе, потому что подменяются вместе: prior.yaml лежит в том же каталоге и
// его опечатка роняет обновление так же, как опечатка в SecLang.
type profile struct {
	engine engine.Engine
	policy prior.Policy
}

func (s *Set) Names() []string {
	names := make([]string, 0, len(s.profiles))

	for name := range s.profiles {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

func (s *Set) RuleCount(name string) int {
	if p, ok := s.profiles[name]; ok {
		return p.engine.RuleCount()
	}

	return 0
}

type Registry struct {
	dir     string
	current atomic.Pointer[Set]

	mu      sync.Mutex
	unknown map[string]int64
}

// Selection -- по какому имени выбран набор правил. Unknown означает
// расхождение конфигурации nginx с набором загруженных профилей; движка в этом
// случае нет вовсе, и именно это расхождение считает счётчик.
type Selection struct {
	Profile string
	Unknown bool
}

func New(cfg *config.Config) (*Registry, error) {
	dir := cfg.ProfilesDir

	// Применённое дерево переживает рестарт, пока watch не догнал KV.
	if HasDefault(cfg.DataDir) {
		dir = cfg.DataDir
	}

	r := &Registry{
		dir:     dir,
		unknown: make(map[string]int64),
	}

	if err := r.Reload(); err != nil {
		return nil, err
	}

	return r, nil
}

// HasDefault — в каталоге есть обязательный profiles/http/default.
func HasDefault(dir string) bool {
	if dir == "" {
		return false
	}

	entries, err := filepath.Glob(filepath.Join(dir, TreeDir, DefaultProfile, "*.conf"))
	return err == nil && len(entries) > 0
}

// Reload собирает новый снимок целиком и публикует его одним присваиванием.
// Ошибка компиляции любого профиля -- это отказ обновления, а не частичное
// применение: действующий снимок остаётся прежним.
func (r *Registry) Reload() error {
	return r.ReloadFrom(r.dir)
}

// ReloadFrom компилирует каталог и подменяет указатель. r.dir становится dir
// только после успеха: провал оставляет боевой набор и прежний путь.
func (r *Registry) ReloadFrom(dir string) error {
	set, err := build(dir)
	if err != nil {
		return err
	}

	r.current.Store(set)
	r.dir = dir

	return nil
}

func (r *Registry) Dir() string { return r.dir }

func (r *Registry) Current() *Set { return r.current.Load() }

// Select возвращает набор правил для тега route.profile.
//
// Пустой тег -- это не ошибка конфигурации, а старый модуль или явное
// отсутствие директивы: протокол предписывает подставлять литерал "default".
func (r *Registry) Select(profile string) (engine.Engine, Selection) {
	return r.selectFrom(r.current.Load().profiles, profile)
}

func (r *Registry) selectFrom(profiles map[string]profile,
	name string) (engine.Engine, Selection) {

	if name == "" {
		name = DefaultProfile
	}

	if p, ok := profiles[name]; ok {
		return p.engine, Selection{Profile: name}
	}

	/*
	 * Профиля нет. Отката на default здесь больше не бывает: чужой набор
	 * правил -- не более мягкая проверка, а проверка не того, и ответ по нему
	 * выдавал бы её за проверку этого маршрута. Вызывающий отвечает error.
	 */
	r.countUnknown(name)

	return nil, Selection{Profile: name, Unknown: true}
}

/*
 * PriorRules -- правила приёма чужих действий для профиля маршрута. Разрешение
 * имени то же, что у Select: пустой тег -- default, неизвестного имени --
 * ничего (тем сообщением всё равно займётся error по неизвестному профилю).
 * Счётчик расхождений здесь не трогается: Select его уже посчитал или
 * посчитает за это же сообщение.
 */
func (r *Registry) PriorRules(name string) []prior.Rule {
	profiles := r.current.Load().profiles

	if name == "" {
		name = DefaultProfile
	}

	if p, ok := profiles[name]; ok {
		return p.policy.Rules
	}

	return nil
}

/*
 * Outcomes -- инициаторы по исходу для профиля маршрута. Разрешение имени то
 * же, что у PriorRules: пустой тег -- default, неизвестного имени -- ничего.
 */
func (r *Registry) Outcomes(name string) []prior.Outcome {
	profiles := r.current.Load().profiles

	if name == "" {
		name = DefaultProfile
	}

	if p, ok := profiles[name]; ok {
		return p.policy.Outcomes
	}

	return nil
}

/*
 * Счётчик расхождений: тег из nginx и загруженные профили живут в двух разных
 * репозиториях конфигурации, и без него разъезд между ними был бы виден только
 * по жалобе на трафик, прошедший не по тому набору правил.
 */
func (r *Registry) countUnknown(profile string) {
	r.mu.Lock()
	r.unknown[profile]++
	r.mu.Unlock()
}

func (r *Registry) UnknownCounts() map[string]int64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make(map[string]int64, len(r.unknown))

	for k, v := range r.unknown {
		out[k] = v
	}

	return out
}

func build(dir string) (*Set, error) {
	profiles, err := buildTree(dir, TreeDir)
	if err != nil {
		return nil, err
	}

	if _, ok := profiles[DefaultProfile]; !ok {
		return nil, fmt.Errorf("profiles: %s/%s is missing and is mandatory",
			TreeDir, DefaultProfile)
	}

	return &Set{profiles: profiles}, nil
}

func buildTree(dir, tree string) (map[string]profile, error) {
	treeDir := filepath.Join(dir, tree)

	entries, err := os.ReadDir(treeDir)
	if err != nil {
		return nil, fmt.Errorf("profiles %s: %w", tree, err)
	}

	set := map[string]profile{}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		name := e.Name()

		files, err := filepath.Glob(filepath.Join(treeDir, name, "*.conf"))
		if err != nil {
			return nil, fmt.Errorf("profile %s/%q: %w", tree, name, err)
		}

		if len(files) == 0 {
			return nil, fmt.Errorf("profile %s/%q has no .conf files", tree, name)
		}

		// Порядок включения -- лексический по имени файла, поэтому нумерация в
		// именах (00-engine.conf, 10-crs-setup.conf) значима.
		sort.Strings(files)

		eng, err := corazaengine.New(root, files)
		if err != nil {
			return nil, fmt.Errorf("profile %s/%q: %w", tree, name, err)
		}

		policy, err := prior.LoadDir(filepath.Join(treeDir, name), func(file string) {
			// Прежнее имя читается одно поколение, и молчать об этом нельзя:
			// иначе переименование заметят по исчезнувшим правилам приёма.
			slog.Warn("policy file has the old name",
				"profile", name, "file", file, "expected", prior.FileName)
		})
		if err != nil {
			return nil, fmt.Errorf("profile %s/%q: %w", tree, name, err)
		}

		set[name] = profile{engine: eng, policy: policy}
	}

	return set, nil
}
