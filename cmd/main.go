package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/tacenva/database"
	tacpass_core "github.com/tacenva/tacpass-core"
	accesscontrolCore "github.com/tacenva/tacpass-core/accesscontrol"
	authCore "github.com/tacenva/tacpass-core/auth"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/permission"
	"github.com/tacenva/tacpass-core/user"
	vaultCore "github.com/tacenva/tacpass-core/vault"
	"github.com/tacenva/tacpass-core/vaultaccess"
	"github.com/tacenva/tacpassd/internal/config"
	"github.com/tacenva/tacpassd/internal/feature/accesscontrol"
	"github.com/tacenva/tacpassd/internal/feature/auth"
	"github.com/tacenva/tacpassd/internal/feature/vault"
	"github.com/tacenva/tacpassd/internal/middleware"
	"github.com/tacenva/tacpassd/internal/server"
	"github.com/tacenva/tacpassd/internal/tls"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	addAdmin := flag.Bool(
		"add-admin",
		false,
		"add admin privilege",
	)

	listUnapproved := flag.Bool(
		"list-unapproved",
		false,
		"list unapproved users",
	)

	approveUserID := flag.String(
		"approve",
		"",
		"approve user by ID",
	)

	publicKey := flag.String(
		"public-key",
		"",
		"public key",
	)

	flag.Parse()

	cfg, err := config.LoadOrCreate()
	if err != nil {
		log.Fatal(err)
	}
	sqliteDB, err := OpenSQLite(
		cfg.Path(config.AppDBFileName),
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := tacpass_core.Migrate(sqliteDB); err != nil {
		log.Fatal(err)
	}

	accesscontrolService,
		authService := getCoreServices(
		sqliteDB,
	)

	if *addAdmin {
		if err := addAdminPrivilege(
			accesscontrolService,
		); err != nil {
			log.Fatal(err)
		}

		return
	}

	if *listUnapproved {
		if err := listUnapprovedUsers(
			accesscontrolService,
			*publicKey,
		); err != nil {
			log.Fatal(err)
		}

		return
	}

	if *approveUserID != "" {
		if err := approveUser(
			accesscontrolService,
			*approveUserID,
		); err != nil {
			log.Fatal(err)
		}

		return
	}

	if err := serve(
		cfg,
		sqliteDB,
		accesscontrolService,
		authService,
	); err != nil {
		log.Fatal(err)
	}
}

func serve(
	cfg *config.Config,
	sqliteDB *gorm.DB,
	accesscontrolService *accesscontrolCore.Service,
	authService *authCore.Service,
) error {
	tacenvaDB := database.New(
		cfg.VaultDir(),
	)

	vaultRepository := vaultCore.NewRepository(
		sqliteDB,
	)

	vaultaccessRepository := vaultaccess.NewRepository(
		sqliteDB,
	)

	vaultaccessService := vaultaccess.NewService(
		vaultaccessRepository,
	)

	vaultService := vaultCore.NewService(
		vaultRepository,
		tacenvaDB,
		vaultaccessService,
	)

	authHandler := auth.NewHandler(
		authService,
	)

	accesscontrolHandler := accesscontrol.NewHandler(
		accesscontrolService,
	)

	vaultHandler := vault.NewHandler(
		vaultService,
		tacenvaDB,
		vaultaccessService,
	)

	authMiddleware := middleware.NewAuth(
		authService,
	)

	router := server.NewRouter(
		authMiddleware,
		authHandler,
		accesscontrolHandler,
		vaultHandler,
	)

	var handler http.Handler = router

	handler = middleware.Debug(handler)
	// if debug {
	// }

	if err := ensureTLS(cfg); err != nil {
		return err
	}

	httpServer := server.New(
		fmt.Sprintf("0.0.0.0:%d", cfg.Server.Port),
		router,
	)

	return httpServer.Run(
		cfg.Path(cfg.TLS.CertFile),
		cfg.Path(cfg.TLS.KeyFile),
	)
}

func ensureTLS(cfg *config.Config) error {
	if _, err := os.Stat(cfg.Path(cfg.TLS.CertFile)); err == nil {
		if _, err := os.Stat(cfg.Path(cfg.TLS.KeyFile)); err == nil {
			return nil
		}
	}

	if err := tls.GenerateSelfSignedCert(
		cfg.Path(cfg.TLS.CertFile),
		cfg.Path(cfg.TLS.KeyFile),
	); err != nil {
		return fmt.Errorf("generate tls certificate: %w", err)
	}

	return nil
}

func OpenSQLite(
	path string,
) (*gorm.DB, error) {
	db, err := gorm.Open(
		sqlite.Open(path),
		&gorm.Config{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"open sqlite database: %w",
			err,
		)
	}

	return db, nil
}

func getCoreServices(
	sqliteDB *gorm.DB,
) (
	*accesscontrolCore.Service,
	*authCore.Service,
) {
	userRepository := user.NewRepository(
		sqliteDB,
	)

	userService := user.NewService(
		userRepository,
	)

	permissionRepository := permission.NewRepository(
		sqliteDB,
	)

	permissionService := permission.NewService(
		permissionRepository,
	)

	accesscontrolService := accesscontrolCore.NewService(
		userService,
		permissionService,
	)

	authService := authCore.NewService(
		userService,
		permissionService,
	)

	return accesscontrolService, authService
}

func addAdminPrivilege(
	accesscontrolService *accesscontrolCore.Service,
) error {
	_, keypair, err := accesscontrolService.Create(
		entity.PrivilegeAdmin,
	)
	if err != nil {
		return err
	}

	fmt.Println(
		"admin keypair created:",
		keypair.PublicKey,
		keypair.PrivateKey,
	)

	return nil
}

func listUnapprovedUsers(
	accesscontrolService *accesscontrolCore.Service,
	publicKey string,
) error {
	if publicKey == "" {
		return fmt.Errorf(
			"--public-key is required",
		)
	}

	permissionData, err := accesscontrolService.GetByPublicKey(
		publicKey,
	)
	if err != nil {
		return err
	}

	users, err := accesscontrolService.UserList(
		permissionData.ID,
	)
	if err != nil {
		return err
	}

	for _, user := range users {
		fmt.Printf(
			"id=%s hostname=%s\n",
			user.ID,
			user.Hostname,
		)
	}

	return nil
}

func approveUser(
	accesscontrolService *accesscontrolCore.Service,
	userID string,
) error {
	user, err := accesscontrolService.ApproveUser(
		userID,
	)
	if err != nil {
		return err
	}

	fmt.Printf(
		"user approved: id=%s hostname=%s\n",
		user.ID,
		user.Hostname,
	)

	return nil
}
