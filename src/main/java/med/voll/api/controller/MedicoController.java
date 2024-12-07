package med.voll.api.controller;

import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import med.voll.api.domain.direccion.DatosDireccion;
import med.voll.api.domain.medico.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@RestController
@RequestMapping("/medicos")
public class MedicoController {
    @Autowired
    private MedicoRepository medicoRepository;
    @PostMapping
    public ResponseEntity<DatosRespuestaMedico> registrarMedico(@RequestBody @Valid DatosRegistroMedico datosRegistroMedico,
                                                                UriComponentsBuilder uriComponentsBuilder){
//        System.out.println("El request llega correctamente");
//        System.out.println(datosRegistroMedico);
        Medico medico= medicoRepository.save(new Medico(datosRegistroMedico));
        DatosRespuestaMedico datosRespuestaMedico=new DatosRespuestaMedico(medico.getId(),medico.getNombre(),medico.getEmail()
                ,medico.getTelefono(),medico.getEspecialidad().toString(),new DatosDireccion(medico.getDireccion().getCalle(),
                medico.getDireccion().getDistrito(),medico.getDireccion().getCiudad(),
                medico.getDireccion().getNumero(),medico.getDireccion().getComplemento()));
        URI url=uriComponentsBuilder.path("/medicos/{id}").buildAndExpand(medico.getId()).toUri();
        return ResponseEntity.created(url).body(datosRespuestaMedico);
        //Return 201 created
        //URL donde entcontrar al medico
        // Get donde encuentre
    }

    //Si quiero traer solo alguna informacion
//    @GetMapping
//    public List<DatosListadoMedico> listadoMedico(){
//        return medicoRepository.findAll().stream()
//                .map(medico->new DatosListadoMedico(medico)).toList();
//    };

    //Si quiero traer solo alguna informacion
    @GetMapping
    public ResponseEntity<Page<DatosListadoMedico>> listadoMedico(@PageableDefault(size = 2) Pageable paginacion){
//        return medicoRepository.findAll(paginacion)
//                .map(medico->new DatosListadoMedico(medico));
        return ResponseEntity.ok(medicoRepository.findByActivoTrue(paginacion)
                .map(medico->new DatosListadoMedico(medico)));
    };

@PutMapping
@Transactional
    public ResponseEntity actualizarMedico(@RequestBody @Valid DatosActualizarMedico datosActualizarMedico){
    Medico medico=medicoRepository.getReferenceById(datosActualizarMedico.id());
    medico.actualizarDatos(datosActualizarMedico);
    return ResponseEntity.ok(new DatosRespuestaMedico(medico.getId(),medico.getNombre(),medico.getEmail()
    ,medico.getTelefono(),medico.getEspecialidad().toString(),new DatosDireccion(medico.getDireccion().getCalle(),
            medico.getDireccion().getDistrito(),medico.getDireccion().getCiudad(),
            medico.getDireccion().getNumero(),medico.getDireccion().getComplemento())));
}

@DeleteMapping("/{id}")
@Transactional
public ResponseEntity eliminarMedico(@PathVariable Long id) {
    Medico medico=medicoRepository.getReferenceById(id);
//    medicoRepository.delete(medico);
    medico.desactivarMedico();
    return ResponseEntity.noContent().build();
}

    @GetMapping("/{id}")
    @Transactional
    public ResponseEntity retornarDatosMedico(@PathVariable Long id) {
        Medico medico=medicoRepository.getReferenceById(id);
//    medicoRepository.delete(medico);
        medico.desactivarMedico();
        var datosMedicos=new DatosRespuestaMedico(medico.getId(),medico.getNombre(),medico.getEmail()
                ,medico.getTelefono(),medico.getEspecialidad().toString(),new DatosDireccion(medico.getDireccion().getCalle(),
                medico.getDireccion().getDistrito(),medico.getDireccion().getCiudad(),
                medico.getDireccion().getNumero(),medico.getDireccion().getComplemento()));
        return ResponseEntity.ok(datosMedicos);
    }

}
