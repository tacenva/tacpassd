package vault

import (
	"errors"
	"strings"

	"github.com/tacenva/database"
	"github.com/tacenva/tacpass-core/entity"
	"github.com/tacenva/tacpass-core/vaultaccess"
)

var ErrForbidden = errors.New("forbidden")

type Service struct {
	tacenvaDB *database.DB
	vaService *vaultaccess.Service
}

func NewService(
	tacenvaDB *database.DB,
	vaService *vaultaccess.Service,
) *Service {
	return &Service{
		tacenvaDB: tacenvaDB,
		vaService: vaService,
	}
}

// CreateRecord menyimpan encrypted record ke vault.
//
// Data harus berupa opaque encrypted bytes.
// Service ini tidak melakukan decrypt, decode, atau deserialize data.
func (s *Service) CreateRecord(
	authUser *entity.User,
	vaultID string,
	data []byte,
) (string, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return "", ErrForbidden
	}

	if len(data) == 0 {
		return "", errors.New("record data cannot be empty")
	}

	if err := s.checkAccess(authUser, vaultID); err != nil {
		return "", err
	}

	fileDB, err := s.tacenvaDB.RawFile(vaultID)
	if err != nil {
		return "", err
	}

	return fileDB.Insert(data)
}

// GetRecord mengambil encrypted record berdasarkan ID.
//
// Data dikembalikan apa adanya tanpa decrypt.
func (s *Service) GetRecord(
	authUser *entity.User,
	vaultID string,
	recordID string,
) ([]byte, error) {
	vaultID = strings.TrimSpace(vaultID)
	recordID = strings.TrimSpace(recordID)

	if vaultID == "" || recordID == "" {
		return nil, ErrForbidden
	}

	if err := s.checkAccess(authUser, vaultID); err != nil {
		return nil, err
	}

	fileDB, err := s.tacenvaDB.RawFile(vaultID)
	if err != nil {
		return nil, err
	}

	return fileDB.Find(recordID)
}

// GetAllRecord mengambil seluruh encrypted record dalam vault.
//
// Data dikembalikan apa adanya tanpa decrypt.
func (s *Service) GetAllRecord(
	authUser *entity.User,
	vaultID string,
) (map[string][]byte, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return nil, ErrForbidden
	}

	if err := s.checkAccess(authUser, vaultID); err != nil {
		return nil, err
	}

	fileDB, err := s.tacenvaDB.RawFile(vaultID)
	if err != nil {
		return nil, err
	}

	return fileDB.FindAll()
}

// UpdateRecord mengganti encrypted data berdasarkan ID.
//
// Data baru dianggap opaque encrypted bytes dan tidak diproses
// oleh daemon.
func (s *Service) UpdateRecord(
	authUser *entity.User,
	vaultID string,
	recordID string,
	data []byte,
) error {
	vaultID = strings.TrimSpace(vaultID)
	recordID = strings.TrimSpace(recordID)

	if vaultID == "" || recordID == "" {
		return ErrForbidden
	}

	if len(data) == 0 {
		return errors.New("record data cannot be empty")
	}

	if err := s.checkAccess(authUser, vaultID); err != nil {
		return err
	}

	fileDB, err := s.tacenvaDB.RawFile(vaultID)
	if err != nil {
		return err
	}

	return fileDB.Update(
		recordID,
		data,
	)
}

// DeleteRecord menghapus encrypted record berdasarkan ID.
func (s *Service) DeleteRecord(
	authUser *entity.User,
	vaultID string,
	recordID string,
) error {
	vaultID = strings.TrimSpace(vaultID)
	recordID = strings.TrimSpace(recordID)

	if vaultID == "" || recordID == "" {
		return ErrForbidden
	}

	if err := s.checkAccess(authUser, vaultID); err != nil {
		return err
	}

	fileDB, err := s.tacenvaDB.RawFile(vaultID)
	if err != nil {
		return err
	}

	return fileDB.Delete(recordID)
}

// checkAccess memastikan user mempunyai akses ke vault.
//
// Daemon hanya melakukan authorization.
// Daemon tidak membutuhkan vault key dan tidak mengetahui isi record.
func (s *Service) checkAccess(
	authUser *entity.User,
	vaultID string,
) error {
	if authUser == nil {
		return ErrForbidden
	}

	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return ErrForbidden
	}

	isAccessible, err := s.vaService.IsVaultAccesible(
		vaultID,
		authUser.PermissionID,
	)
	if err != nil {
		return err
	}

	if !isAccessible {
		return ErrForbidden
	}

	return nil
}

func (s *Service) OutOfSync(
	authUser *entity.User,
	vaultID string,
	replicaHashVal string,
) (bool, error) {
	vaultID = strings.TrimSpace(vaultID)

	if vaultID == "" {
		return false, ErrForbidden
	}

	fileDB, err := s.tacenvaDB.RawFile(vaultID)
	if err != nil {
		return false, err
	}

	same, err := fileDB.CompareHash(replicaHashVal)
	if err != nil {
		return false, err
	}

	return !same, nil
}
