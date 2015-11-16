package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/flynn/flynn/Godeps/_workspace/src/github.com/jackc/pgx"
	"github.com/flynn/flynn/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/flynn/flynn/controller/schema"
	ct "github.com/flynn/flynn/controller/types"
	"github.com/flynn/flynn/pkg/ctxhelper"
	"github.com/flynn/flynn/pkg/httphelper"
	"github.com/flynn/flynn/pkg/postgres"
	"github.com/flynn/flynn/pkg/sse"
)

type formationKey struct {
	AppID, ReleaseID string
}

type FormationRepo struct {
	db        *postgres.DB
	apps      *AppRepo
	releases  *ReleaseRepo
	artifacts *ArtifactRepo

	subscriptions map[chan *ct.ExpandedFormation]struct{}
	stopListener  chan struct{}
	subMtx        sync.RWMutex
}

func NewFormationRepo(db *postgres.DB, appRepo *AppRepo, releaseRepo *ReleaseRepo, artifactRepo *ArtifactRepo) *FormationRepo {
	return &FormationRepo{
		db:            db,
		apps:          appRepo,
		releases:      releaseRepo,
		artifacts:     artifactRepo,
		subscriptions: make(map[chan *ct.ExpandedFormation]struct{}),
		stopListener:  make(chan struct{}),
	}
}

func (r *FormationRepo) validateFormProcs(f *ct.Formation) error {
	release, err := r.releases.Get(f.ReleaseID)
	if err != nil {
		return err
	}
	rel := release.(*ct.Release)
	invalid := make([]string, 0, len(f.Processes))
	for k := range f.Processes {
		if _, ok := rel.Processes[k]; !ok {
			invalid = append(invalid, k)
		}
	}
	if len(invalid) > 0 {
		return ct.ValidationError{Message: fmt.Sprintf("Requested formation includes process types that do not exist in release. Invalid process types: [%s]", strings.Join(invalid, ", "))}
	}
	return nil
}

func (r *FormationRepo) Add(f *ct.Formation) error {
	if err := r.validateFormProcs(f); err != nil {
		return err
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	scale := &ct.Scale{
		Processes: f.Processes,
		ReleaseID: f.ReleaseID,
	}
	prevFormation, _ := r.Get(f.AppID, f.ReleaseID)
	if prevFormation != nil {
		scale.PrevProcesses = prevFormation.Processes
	}
	err = tx.QueryRow("formation_insert", f.AppID, f.ReleaseID, f.Processes).Scan(&f.CreatedAt, &f.UpdatedAt)
	if postgres.IsUniquenessError(err, "") {
		tx.Rollback()
		tx, err = r.db.Begin()
		if err != nil {
			return err
		}
		err = tx.QueryRow("formation_update", f.AppID, f.ReleaseID, f.Processes).Scan(&f.CreatedAt, &f.UpdatedAt)
	}
	if err != nil {
		tx.Rollback()
		return err
	}
	if err := createEvent(tx.Exec, &ct.Event{
		AppID:      f.AppID,
		ObjectID:   f.AppID + ":" + f.ReleaseID,
		ObjectType: ct.EventTypeScale,
	}, scale); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func scanFormation(s postgres.Scanner) (*ct.Formation, error) {
	f := &ct.Formation{}
	err := s.Scan(&f.AppID, &f.ReleaseID, &f.Processes, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			err = ErrNotFound
		}
		return nil, err
	}
	return f, err
}

func scanExpandedFormation(s postgres.Scanner) (*ct.ExpandedFormation, error) {
	f := &ct.ExpandedFormation{
		App:      &ct.App{},
		Release:  &ct.Release{},
		Artifact: &ct.Artifact{},
	}
	var artifactID *string
	err := s.Scan(
		&f.App.ID,
		&f.App.Name,
		&f.Release.ID,
		&artifactID,
		&f.Release.Meta,
		&f.Release.Env,
		&f.Release.Processes,
		&f.Artifact.ID,
		&f.Artifact.Type,
		&f.Artifact.URI,
		&f.Processes,
		&f.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			err = ErrNotFound
		}
		return nil, err
	}
	if artifactID != nil {
		f.Release.ArtifactID = *artifactID
	}
	return f, nil
}

func (r *FormationRepo) Get(appID, releaseID string) (*ct.Formation, error) {
	row := r.db.QueryRow("formation_select", appID, releaseID)
	return scanFormation(row)
}

func (r *FormationRepo) List(appID string) ([]*ct.Formation, error) {
	rows, err := r.db.Query("formation_list_by_app", appID)
	if err != nil {
		return nil, err
	}
	formations := []*ct.Formation{}
	for rows.Next() {
		formation, err := scanFormation(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		formations = append(formations, formation)
	}
	return formations, nil
}

func (r *FormationRepo) ListActive() ([]*ct.ExpandedFormation, error) {
	rows, err := r.db.Query("formation_list_active")
	if err != nil {
		return nil, err
	}
	formations := []*ct.ExpandedFormation{}
	for rows.Next() {
		formation, err := scanExpandedFormation(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		formations = append(formations, formation)
	}
	return formations, nil
}

func (r *FormationRepo) Remove(appID, releaseID string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	scale := &ct.Scale{
		ReleaseID: releaseID,
	}
	prevFormation, _ := r.Get(appID, releaseID)
	if prevFormation != nil {
		scale.PrevProcesses = prevFormation.Processes
	}
	err = tx.Exec("formation_delete", appID, releaseID)
	if err != nil {
		tx.Rollback()
		return err
	}
	if err := createEvent(tx.Exec, &ct.Event{
		AppID:      appID,
		ObjectID:   appID + ":" + releaseID,
		ObjectType: ct.EventTypeScale,
	}, scale); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (r *FormationRepo) publish(appID, releaseID string) {
	formation, err := r.Get(appID, releaseID)
	if err == ErrNotFound {
		// formation delete event
		updated_at := time.Now()
		formation = &ct.Formation{AppID: appID, ReleaseID: releaseID, UpdatedAt: &updated_at}
	} else if err != nil {
		// TODO: log error
		return
	}

	f, err := r.expandFormation(formation)
	if err != nil {
		// TODO: log error
		return
	}
	r.subMtx.RLock()
	defer r.subMtx.RUnlock()

	for ch := range r.subscriptions {
		ch <- f
	}
}

func (r *FormationRepo) expandFormation(formation *ct.Formation) (*ct.ExpandedFormation, error) {
	app, err := r.apps.Get(formation.AppID)
	if err == ErrNotFound {
		app = &ct.App{ID: formation.AppID}
	} else if err != nil {
		return nil, err
	}
	release, err := r.releases.Get(formation.ReleaseID)
	if err != nil {
		return nil, err
	}
	artifact, err := r.artifacts.Get(release.(*ct.Release).ArtifactID)
	if err != nil {
		return nil, err
	}
	f := &ct.ExpandedFormation{
		App:       app.(*ct.App),
		Release:   release.(*ct.Release),
		Artifact:  artifact.(*ct.Artifact),
		Processes: formation.Processes,
		UpdatedAt: *formation.UpdatedAt,
	}
	return f, nil
}

func (r *FormationRepo) startListener() error {
	log := logger.New("fn", "FormationRepo.startListener")
	listener, err := r.db.Listen("formations", log)
	if err != nil {
		return err
	}
	go func() {
		for {
			select {
			case n, ok := <-listener.Notify:
				if !ok {
					r.unsubscribeAll()
					return
				}
				ids := strings.SplitN(n.Payload, ":", 2)
				go r.publish(ids[0], ids[1])
			case <-r.stopListener:
				listener.Close()
				return
			}
		}
	}()
	return nil
}

func (r *FormationRepo) unsubscribeAll() {
	r.subMtx.Lock()
	defer r.subMtx.Unlock()

	for ch := range r.subscriptions {
		r.unsubscribeLocked(ch)
		close(ch)
	}
}

func (r *FormationRepo) Subscribe(ch chan *ct.ExpandedFormation, stopCh <-chan struct{}, since time.Time) error {
	// we need to keep the mutex locked whilst calling startListener
	// to avoid a race where multiple subscribers can get added to
	// r.subscriptions before a potentially failed listener start,
	// meaning subsequent subscribers wont try to start the listener.
	r.subMtx.Lock()
	defer r.subMtx.Unlock()

	if len(r.subscriptions) == 0 {
		if err := r.startListener(); err != nil {
			return err
		}
	}
	r.subscriptions[ch] = struct{}{}

	go r.sendUpdatedSince(ch, stopCh, since)
	return nil
}

func (r *FormationRepo) sendUpdatedSince(ch chan *ct.ExpandedFormation, stopCh <-chan struct{}, since time.Time) error {
	rows, err := r.db.Query("formation_list_since", since)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		formation, err := scanFormation(rows)
		if err != nil {
			return err
		}
		ef, err := r.expandFormation(formation)
		if err != nil {
			return err
		}
		select {
		case ch <- ef:
		case <-stopCh:
			return nil
		}
	}
	ch <- &ct.ExpandedFormation{} // sentinel
	return rows.Err()
}

func (r *FormationRepo) Unsubscribe(ch chan *ct.ExpandedFormation) {
	r.subMtx.Lock()
	defer r.subMtx.Unlock()
	r.unsubscribeLocked(ch)
}

func (r *FormationRepo) unsubscribeLocked(ch chan *ct.ExpandedFormation) {
	go func() {
		// drain to prevent deadlock while removing the listener
		for range ch {
		}
	}()
	delete(r.subscriptions, ch)
	if len(r.subscriptions) == 0 {
		select {
		case r.stopListener <- struct{}{}:
		default:
		}
	}
}

func (c *controllerAPI) PutFormation(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	app := c.getApp(ctx)
	release, err := c.getRelease(ctx)
	if err != nil {
		respondWithError(w, err)
		return
	}

	var formation ct.Formation
	if err = httphelper.DecodeJSON(req, &formation); err != nil {
		respondWithError(w, err)
		return
	}

	if release.ArtifactID == "" {
		respondWithError(w, ct.ValidationError{Message: "release is not deployable"})
		return
	}

	formation.AppID = app.ID
	formation.ReleaseID = release.ID

	if err = schema.Validate(formation); err != nil {
		respondWithError(w, err)
		return
	}

	if err = c.formationRepo.Add(&formation); err != nil {
		respondWithError(w, err)
		return
	}
	httphelper.JSON(w, 200, &formation)
}

func (c *controllerAPI) GetFormation(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	params, _ := ctxhelper.ParamsFromContext(ctx)

	app := c.getApp(ctx)
	formation, err := c.formationRepo.Get(app.ID, params.ByName("releases_id"))
	if err != nil {
		respondWithError(w, err)
		return
	}
	httphelper.JSON(w, 200, formation)
}

func (c *controllerAPI) DeleteFormation(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	params, _ := ctxhelper.ParamsFromContext(ctx)

	app := c.getApp(ctx)
	formation, err := c.formationRepo.Get(app.ID, params.ByName("releases_id"))
	if err != nil {
		respondWithError(w, err)
		return
	}
	err = c.formationRepo.Remove(app.ID, formation.ReleaseID)
	if err != nil {
		respondWithError(w, err)
		return
	}
	w.WriteHeader(200)
}

func (c *controllerAPI) ListFormations(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	app := c.getApp(ctx)
	list, err := c.formationRepo.List(app.ID)
	if err != nil {
		respondWithError(w, err)
		return
	}
	httphelper.JSON(w, 200, list)
}

func (c *controllerAPI) GetFormations(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	if strings.Contains(req.Header.Get("Accept"), "text/event-stream") {
		c.streamFormations(ctx, w, req)
		return
	}

	if req.URL.Query().Get("active") == "true" {
		list, err := c.formationRepo.ListActive()
		if err != nil {
			respondWithError(w, err)
			return
		}
		httphelper.JSON(w, 200, list)
	}

	// don't return a list of all formations, there will be lots of them
	// and no components currently need such a list
	httphelper.ValidationError(w, "", "must either request a stream or only active formations")
}

func (c *controllerAPI) streamFormations(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	ch := make(chan *ct.ExpandedFormation)
	stopCh := make(chan struct{})
	since, err := time.Parse(time.RFC3339, req.FormValue("since"))
	if err != nil {
		respondWithError(w, err)
		return
	}
	if err := c.formationRepo.Subscribe(ch, stopCh, since); err != nil {
		respondWithError(w, err)
		return
	}
	defer c.formationRepo.Unsubscribe(ch)
	defer close(stopCh)
	l, _ := ctxhelper.LoggerFromContext(ctx)
	sse.ServeStream(w, ch, l)
}
