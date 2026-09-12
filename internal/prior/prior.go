/*
 * Просьбы соседей: правила приёма чужих действий и их применение.
 *
 * Это единственное место, где действие из prior что-то значит: без правила в
 * профиле просьба соседа не применяется вовсе (docs/inspector-actions.md,
 * «Сторона получателя»). Из словаря инспектор применяет два глагола:
 *
 *   threshold -- коэффициент к счёту, который инспектор отдаёт модулю на этом
 *               запросе: проценты, множитель 1 + delta/100. Плюс -- поведение
 *               клиента дороже (строже), минус -- скидка (мягче). Пороги --
 *               и свои, и модуля -- не двигаются вовсе. Знак выбирает
 *               отправитель на проводе, потолок |процента| -- правило.
 *   skip      -- не проверять этот запрос вовсе.
 *
 * Правила лежат в profiles/http/<профиль>/prior.yaml, по образцу секции
 * trigger.prior капчи. Файла нет -- инспектор никого не слушает, и это обычное
 * состояние, а не незаполненная форма. Файл с опечаткой обязан уронить загрузку
 * набора целиком, как и опечатка в SecLang.
 */

package prior

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	yaml "github.com/goccy/go-yaml"

	"github.com/exemt/placitum-modsec/internal/protocol"
)

/*
 * FileName -- имя файла политики в каталоге профиля, рядом с *.conf. В нём
 * живут обе стороны канала: правила приёма (prior) и инициаторы по исходу
 * (outcomes) -- разносить их по двум файлам значило бы дать им разъехаться.
 *
 * LegacyFileName читается одно поколение: файлы с прежним именем лежат на
 * нодах, и молча перестать их слушать -- худший способ выкатить переименование.
 */
const (
	FileName       = "policy.yaml"
	LegacyFileName = "prior.yaml"
)

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	codeRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

// AnyInspector в поле from -- сигнал принимается от любого соседа. Для этого
// инспектора он не проходит валидацию никогда: skip ослабляет всегда, у
// threshold знак (то есть скидку) выбирает отправитель на проводе, и загрузчик
// его не видит. Константа остаётся ради внятного текста ошибки и симметрии со
// словарём канала.
const AnyInspector = "*"

/*
 * Rule -- что мы принимаем от соседа. Правило не умеет срабатывать на число
 * соседа из prior: score -- внутренняя шкала соседа без обещания
 * стабильности. «Мне этого достаточно» говорит отправитель действием, а не
 * получатель по чужому числу.
 */
type Rule struct {
	From   string   `yaml:"from"`
	Accept []string `yaml:"accept"`
	// Apply -- какие оси правило принимает. Без ключа -- любая допустимая при
	// этих глаголах; у threshold и skip она и так одна -- этот запрос.
	Apply []string `yaml:"apply"`
	Codes []string `yaml:"codes"`

	// Deprecated: потолок на |delta| умер -- правило приёма решает «от кого,
	// что и по какому поводу», числа держит загрузчик отправителя
	// (-100..+900). Оба имени -- новое и времён абсолютного сдвига порога --
	// читаются и игнорируются одно поколение, чтобы раскатка нового формата
	// не спотыкалась о policy.yaml, напечатанные до неё; потом станут ошибкой.
	MaxPercent int `yaml:"max_percent"`
	MaxDelta   int `yaml:"max_delta"`
}

// Accepts -- принимает ли правило этот глагол.
func (r Rule) Accepts(verb string) bool {
	for _, v := range r.Accept {
		if v == verb {
			return true
		}
	}

	return false
}

// WantsAxis -- проходит ли ось через фильтр правила. Пустой список означает
// «любая допустимая при этих глаголах».
func (r Rule) WantsAxis(axis string) bool {
	if len(r.Apply) == 0 {
		return true
	}

	for _, a := range r.Apply {
		if a == axis {
			return true
		}
	}

	return false
}

// WantsCode -- проходит ли повод действия через фильтр правила. Пустой список
// означает «любой повод», в том числе отсутствующий.
func (r Rule) WantsCode(code string) bool {
	if len(r.Codes) == 0 {
		return true
	}

	for _, c := range r.Codes {
		if c == code {
			return true
		}
	}

	return false
}

/*
 * Load читает правила профиля. Отсутствие файла -- не ошибка: профиль без
 * единого правила просто никого не слушает. Всё, что проверяется, проверяется
 * здесь, при загрузке: правило с опечаткой обязано не подняться, а не молча
 * не сработать на живом трафике.
 */
/*
 * Policy -- обе стороны канала для одного профиля: кого слушаем и что делаем
 * сами. Пустая политика -- обычное состояние, а не незаполненная форма.
 */
type Policy struct {
	Rules    []Rule
	Outcomes []Outcome
}

// LoadDir -- политика профиля из его каталога. Сначала policy.yaml, следом --
// прежнее имя: файлы с ним лежат на нодах, и перестать их слушать молча
// значило бы выключить чужие правила приёма без единой строки в логе.
func LoadDir(dir string, log func(string)) (Policy, error) {
	p, ok, err := loadFile(filepath.Join(dir, FileName))
	if err != nil || ok {
		return p, err
	}

	p, ok, err = loadFile(filepath.Join(dir, LegacyFileName))
	if err != nil {
		return p, err
	}

	if ok && log != nil {
		log(LegacyFileName)
	}

	return p, nil
}

/*
 * Load -- политика из файла по пути. Файла нет -- инспектор никого не слушает
 * и никого не просит; файл с опечаткой обязан уронить загрузку набора целиком,
 * как и опечатка в SecLang: правило, которое молча не грузится, -- дыра, а не
 * умолчание.
 */
func Load(path string) (Policy, error) {
	p, _, err := loadFile(path)
	return p, err
}

func loadFile(path string) (Policy, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Policy{}, false, nil
		}

		return Policy{}, false, err
	}

	name := filepath.Base(path)

	var doc struct {
		Prior    []Rule    `yaml:"prior"`
		Outcomes []Outcome `yaml:"outcomes"`
	}

	if err := yaml.UnmarshalWithOptions(raw, &doc, yaml.DisallowUnknownField()); err != nil {
		return Policy{}, false, fmt.Errorf("%s: %w", name, err)
	}

	for i, r := range doc.Prior {
		if err := validate(i, r); err != nil {
			return Policy{}, false, fmt.Errorf("%s: %w", name, err)
		}
	}

	for i, o := range doc.Outcomes {
		if err := validateOutcome(i, o); err != nil {
			return Policy{}, false, fmt.Errorf("%s: %w", name, err)
		}
	}

	return Policy{Rules: doc.Prior, Outcomes: doc.Outcomes}, true, nil
}

/*
 * validate -- ограничения загрузчика. Модель угрозы одна: один инспектор
 * скомпрометирован или сломан. Оба наших глагола ослабляют защиту -- skip
 * всегда, у threshold знак выбирает отправитель, -- поэтому послабление
 * требует имени отправителя, и широковещательного правила у этого инспектора
 * не бывает вовсе.
 */
func validate(i int, r Rule) error {
	if r.From == "" {
		return fmt.Errorf("prior[%d]: from is empty", i)
	}

	if len(r.Accept) == 0 {
		return fmt.Errorf("prior[%d]: accept is required", i)
	}

	for _, verb := range r.Accept {
		switch verb {
		case protocol.DoThreshold, protocol.DoSkip:

		case protocol.DoChallenge, protocol.DoReauth, protocol.DoNote:
			return fmt.Errorf("prior[%d]: %q is not ours to apply", i, verb)

		default:
			return fmt.Errorf("prior[%d]: unknown verb %q", i, verb)
		}
	}

	for _, axis := range r.Apply {
		switch axis {
		case protocol.ApplyRequest:

		case protocol.ApplyIP, protocol.ApplyASN, protocol.ApplySession:
			return fmt.Errorf("prior[%d]: axis %q never occurs with %v",
				i, axis, r.Accept)

		default:
			return fmt.Errorf("prior[%d]: unknown axis %q", i, axis)
		}
	}

	if r.From == AnyInspector {
		return fmt.Errorf("prior[%d]: %v need a named sender: they always weaken",
			i, r.Accept)
	}

	return nil
}

/*
 * Ask -- что соседи попросили и что из этого прошло через правила профиля.
 * Нулевая структура означает «никто ничего не просил либо ни одно правило не
 * подошло», и это самый частый исход.
 */
type Ask struct {
	// Skip -- не проверять этот запрос вовсе. Действует только через правило с
	// именем отправителя, поэтому это решение оператора, а не соседа.
	Skip bool
	// Percent -- суммарный коэффициент к отдаваемому счёту в процентах, уже
	// срезанный потолками правил; сумма прижата к -100..+900 -- ниже нуля
	// измерения не бывает.
	Percent int
	// Outcomes -- по строке на каждую доставленную просьбу, для kind=inspector.
	Outcomes []ActionOutcome
}

// Исход одной просьбы. «Нет правила» -- полноправный исход, а не пропуск:
// молчание в ответ на просьбу и есть тот случай, который потом разбирают.
const (
	OutcomeApplied = "applied"
	OutcomeNoRule  = "no_rule"
)

/*
 * ActionOutcome -- что сосед просил и что из этого вышло у нас. Без исхода
 * запись бесполезна: видно, что просьба была, и не видно, почему ничего не
 * случилось.
 *
 * Исходы «не доставлено» сюда попасть не могут по построению -- пассивный
 * отправитель, переполнение waf_actions_max и урезание по маршруту отсекаются
 * до нас, и живут они в записи модуля kind=request.
 */
type ActionOutcome struct {
	From  string `json:"from"`
	Do    string `json:"do"`
	Apply string `json:"apply"`
	Code  string `json:"code,omitempty"`
	Delta int    `json:"delta,omitempty"`
	Value int    `json:"value,omitempty"`

	// Took -- что мы взяли на самом деле: срезанный либо принятый процент.
	Took    int    `json:"took,omitempty"`
	Outcome string `json:"outcome"`
}

/*
 * Evaluate -- все просьбы всех записей prior против правил профиля. Фазы не
 * фильтруются: секция сквозная, просьба с фазы запроса действует и на фазе
 * ответа -- «этот запрос» покрывает обе стороны транзакции. Своих записей в
 * prior не бывает, их не кладёт модуль.
 */
// Границы суммарного коэффициента: -100 -- измерение в ноль, +900 -- вдесятеро.
const (
	PercentMin = -100
	PercentMax = 900
)

func Evaluate(entries []protocol.PriorVerdict, rules []Rule) Ask {
	var a Ask

	for _, v := range entries {
		for _, act := range v.Actions {
			a.deliver(v.Inspector, act, rules)
		}
	}

	if a.Percent < PercentMin {
		a.Percent = PercentMin
	}

	if a.Percent > PercentMax {
		a.Percent = PercentMax
	}

	return a
}

/*
 * deliver -- одна просьба против всех правил профиля. Цикл по действиям
 * снаружи, а не по правилам: исход у просьбы один, сколько бы правил её ни
 * зацепило, и собрать его можно только здесь.
 */
func (a *Ask) deliver(from string, act protocol.Action, rules []Rule) {
	out := ActionOutcome{
		From:    from,
		Do:      act.Do,
		Apply:   act.Scope(),
		Code:    act.Code,
		Delta:   act.Delta,
		Value:   act.Value,
		Outcome: OutcomeNoRule,
	}

	for _, r := range rules {
		if r.From != from {
			continue
		}

		if !r.Accepts(act.Do) || !r.WantsAxis(act.Scope()) || !r.WantsCode(act.Code) {
			continue
		}

		a.take(r, act, &out)
	}

	a.Outcomes = append(a.Outcomes, out)
}

func (a *Ask) take(r Rule, act protocol.Action, out *ActionOutcome) {
	switch act.Do {
	case protocol.DoSkip:
		a.Skip = true
		out.apply(0)

	case protocol.DoThreshold:
		a.Percent += act.Delta
		out.apply(act.Delta)
	}
}

/*
 * apply -- правило подошло и просьба взята целиком: числа держит загрузчик
 * отправителя, получатель их не режет. Одну просьбу может зацепить несколько
 * правил -- took складывается, исход у просьбы один.
 */
func (o *ActionOutcome) apply(took int) {
	o.Outcome = OutcomeApplied
	o.Took += took
}
